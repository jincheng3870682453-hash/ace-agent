#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
guardian.py —— 物理快照回滚

契约（execution_layer.py）：
    from guardian import Guardian
    g = Guardian(str(project_root))
    snapshot_id = g.snapshot(tag)      # 返回快照 id（空项目返回 None）
    ok = g.rollback(snapshot_id)       # 完整性预检 → 备份当前状态 → 恢复 → 验证 → 清理备份

机制（与 system prompt 对齐）：
    1. 写入操作前自动创建项目快照（完整文件树，排除 .git / __pycache__ / .venv 等）
    2. 回滚前执行完整性预检：快照非空、元信息完整、文件校验和一致
    3. 回滚时先备份当前状态，再恢复快照，恢复成功后清理备份
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EXCLUDE_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
                ".idea", ".vscode", ".guardian", ".agent_flywheel",
                ".poc_reports", ".sandbox_tmp", ".test_tmp",
                ".ace_shots", ".ace_images"}
# SEC-04：快照是明文副本，绝不能把用户凭据/密钥文件再复制一份进 .guardian。
# 命中这些名字的文件不进快照（也就不进 meta、不会被回滚重建）。
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
                       ".ovpn", ".ppk", ".asc")
_SENSITIVE_BASENAMES = {".env", ".ai_code.json", ".claude.json"}
_PRIVATE_KEY_PREFIXES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")


def _is_sensitive_file(path: Path) -> bool:
    low = path.name.lower()
    if low in _SENSITIVE_BASENAMES or low.startswith(".env."):
        return True
    if low.startswith(_PRIVATE_KEY_PREFIXES):
        return True
    if low.endswith(_SENSITIVE_SUFFIXES):
        return True
    return False


class SnapshotError(Exception):
    pass


class Guardian:
    """物理快照管理器"""

    def __init__(self, project_root: str, store_dir: Optional[str] = None,
                 signing_key: Optional[str] = None, max_snapshots: int = 20) -> None:
        self.project_root = Path(project_root).resolve()
        self.store = Path(store_dir) if store_dir else self.project_root / ".guardian"
        self.snap_dir = self.store / "snapshots"
        self.backup_dir = self.store / "rollback_backups"
        # SEC-04：签名默认开启。显式提供 signing_key 用配置值；
        # 否则用/建**本项目持久密钥**（存 .guardian/signing_key —— 该目录对 Agent
        # 只读不可写删，宿主侧同用户可读）。持久化是为了让 /undo、重启后的
        # rollback 等**另一个 Guardian 实例**能验同一批快照的签名。
        self.store.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key
        if self.signing_key is None:
            _key_path = self.store / "signing_key"
            if _key_path.exists():
                self.signing_key = _key_path.read_text(encoding="utf-8").strip()
            if not self.signing_key:
                self.signing_key = secrets.token_hex(32)
                _key_path.write_text(self.signing_key, encoding="utf-8")
        self.max_snapshots = max_snapshots  # 快照数量硬上限，超出自动清理最旧的
        for d in (self.snap_dir, self.backup_dir):
            d.mkdir(parents=True, exist_ok=True)

    def _sign(self, content: str) -> str:
        """对快照元信息做 HMAC-SHA256 签名（防伪造）"""
        return hmac.new(self.signing_key.encode("utf-8"),
                        content.encode("utf-8"), hashlib.sha256).hexdigest()

    # ---------- 工具 ----------

    def _collect_files(self) -> List[Path]:
        """收集项目完整文件树（排除构建/缓存/自身存储目录/敏感凭据文件）"""
        files: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.project_root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if _is_sensitive_file(p):
                    continue
                files.append(p)
        return files

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ---------- 快照 ----------

    def snapshot(self, tag: str = "") -> Optional[str]:
        """创建物理快照（完整拷贝文件树），返回快照 id；空项目返回 None"""
        files = self._collect_files()
        if not files:
            return None  # 空项目没有可备份内容
        tag = re.sub(r"[^\w\-]+", "_", tag or "snap")[:40]
        # 随机后缀：防止同一毫秒内多次快照 id 撞车，同时避免 id 可预测
        snap_id = f"{int(time.time() * 1000)}_{tag}_{uuid.uuid4().hex[:6]}"
        dest_root = self.snap_dir / snap_id
        files_dest = dest_root / "files"
        meta = {
            "id": snap_id,
            "tag": tag,
            "created": time.time(),
            "created_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
            "root": str(self.project_root),
            "file_count": len(files),
            "files": {},
        }
        for src in files:
            rel = src.relative_to(self.project_root)
            dst = files_dest / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            meta["files"][rel.as_posix()] = {
                "size": src.stat().st_size,
                "sha256": self._sha256(src),
            }
        # 元信息原子写入（配置签名密钥时附 HMAC 签名）
        meta_path = dest_root / "meta.json"
        tmp_path = meta_path.with_suffix(".json.tmp")
        meta_text = json.dumps(meta, ensure_ascii=False, indent=2)
        tmp_path.write_text(meta_text, encoding="utf-8")
        tmp_path.replace(meta_path)
        if self.signing_key:
            (dest_root / "meta.json.sig").write_text(
                self._sign(meta_text), encoding="utf-8")
        # 创建后立即自检
        ok, reason = self.verify_snapshot(snap_id)
        if not ok:
            shutil.rmtree(dest_root, ignore_errors=True)
            raise SnapshotError(f"快照创建后完整性校验失败: {reason}")
        # 自动清理：快照数量超出上限时删除最旧的（防备份爆炸）
        if self.max_snapshots > 0:
            self.prune(keep=self.max_snapshots)
        return snap_id

    # ---------- 完整性预检 ----------

    def verify_snapshot(self, snap_id: str) -> Tuple[bool, str]:
        """回滚前完整性预检：快照非空、元信息完整、文件校验和一致"""
        dest_root = self.snap_dir / snap_id
        meta_path = dest_root / "meta.json"
        if not meta_path.exists():
            return False, "快照元信息不存在"
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            return False, f"快照元信息损坏: {e}"
        required = {"id", "root", "file_count", "files"}
        if not required.issubset(meta) or not isinstance(meta["files"], dict):
            return False, "快照元信息不完整"
        # 签名校验（配置了签名密钥时）
        if self.signing_key:
            sig_path = dest_root / "meta.json.sig"
            if not sig_path.exists():
                return False, "快照缺少签名文件（当前开启签名校验）"
            expected = self._sign(meta_path.read_text(encoding="utf-8"))
            if sig_path.read_text(encoding="utf-8").strip() != expected:
                return False, "快照签名校验失败（元信息可能被篡改）"
        files_dest = dest_root / "files"
        if not files_dest.is_dir() or meta["file_count"] <= 0 or not meta["files"]:
            return False, "快照为空（无文件内容）"
        for rel, info in meta["files"].items():
            fp = files_dest / rel
            if not fp.exists():
                return False, f"快照文件缺失: {rel}"
            if info.get("sha256") and self._sha256(fp) != info["sha256"]:
                return False, f"快照文件校验和不匹配: {rel}"
        return True, "ok"

    # ---------- 回滚 ----------

    def rollback(self, snap_id: str) -> bool:
        """回滚到指定快照：预检 → 备份当前状态 → 恢复 → 验证 → 清理备份"""
        # 1. 完整性预检
        ok, reason = self.verify_snapshot(snap_id)
        if not ok:
            raise SnapshotError(f"回滚前完整性预检失败: {reason}")
        # 2. 备份当前状态
        ts = time.strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"{ts}_{snap_id}"
        for src in self._collect_files():
            rel = src.relative_to(self.project_root)
            dst = backup_path / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        # 3. 恢复快照
        meta = json.loads((self.snap_dir / snap_id / "meta.json").read_text(encoding="utf-8"))
        files_dest = self.snap_dir / snap_id / "files"
        for src in self._collect_files():
            src.unlink(missing_ok=True)
        for rel, _info in meta["files"].items():
            src = files_dest / rel
            dst = self.project_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        # 4. 验证恢复
        restored = 0
        for rel, info in meta["files"].items():
            fp = self.project_root / rel
            if fp.exists() and self._sha256(fp) == info["sha256"]:
                restored += 1
        if restored != meta["file_count"]:
            # 恢复不完整：保留备份供人工处理
            return False
        # 5. 清理备份
        shutil.rmtree(backup_path, ignore_errors=True)
        return True

    # ---------- 管理 ----------

    def list_snapshots(self) -> List[Dict]:
        out: List[Dict] = []
        for d in sorted(self.snap_dir.iterdir()):
            mp = d / "meta.json"
            if d.is_dir() and mp.exists():
                try:
                    meta = json.loads(mp.read_text(encoding="utf-8"))
                    out.append({
                        "id": meta["id"],
                        "tag": meta.get("tag"),
                        "created_iso": meta.get("created_iso"),
                        "file_count": meta["file_count"],
                    })
                except (json.JSONDecodeError, KeyError):
                    continue
        return out

    def prune(self, keep: int = 10) -> int:
        snaps = self.list_snapshots()
        to_remove = snaps if keep <= 0 else snaps[:-keep]
        removed = 0
        for s in to_remove:
            shutil.rmtree(self.snap_dir / s["id"], ignore_errors=True)
            removed += 1
        return removed


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Guardian 物理快照回滚")
    parser.add_argument("--project", default=".")
    parser.add_argument("--list", action="store_true", help="列出所有快照")
    args = parser.parse_args()
    g = Guardian(args.project)
    if args.list:
        print(json.dumps(g.list_snapshots(), ensure_ascii=False, indent=2))
    else:
        sid = g.snapshot("manual")
        print(f"快照创建: {sid}")
