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
import json
import os
import re
import secrets
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, List, Mapping, NamedTuple, Optional, Tuple

EXCLUDE_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
                ".idea", ".vscode", ".guardian", ".agent_flywheel",
                ".poc_reports", ".sandbox_tmp", ".test_tmp",
                ".ace_shots", ".ace_images"}

# SEC-014：这些文件**不进快照、也不进回滚备份**，只记录"存在过 + 内容哈希"。
#
# 原实现按"整棵文件树"拷贝，于是项目里的 .env、*.pem、id_rsa 被逐轮明文复制到
# .guardian/snapshots/<id>/files/ 下，最多留 max_snapshots 份。后果不是"模型能读到"
# （它本来就能读原文件），而是**扩散与留存**：轮换过的旧密钥在快照里继续以明文存在，
# 一份被打包/同步/误提交的项目目录会把它们一起带走，而用户以为自己只备份了代码。
#
# 代价说清楚：回滚不再恢复这些文件的内容。这是有意的取舍 ——
# 回滚是"撤销对代码的改动"的安全网，不是密钥仓库的备份；而且不备份的另一面是
# 回滚也**不会删除**它们（unlink 走的是同一份收集结果），所以磁盘上的现状会原样保留。
# 内容真的被改过时，sensitive_drift() 会把它列出来，让人知道有一份东西需要手工处理，
# 而不是静默丢失。
SENSITIVE_FILE_NAMES = {".env", ".envrc", ".netrc", "_netrc", ".npmrc", ".pypirc",
                        ".git-credentials", ".htpasswd", "credentials",
                        "authorized_keys", "key4.db", "logins.json",
                        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SENSITIVE_FILE_SUFFIXES = (".pem", ".pfx", ".p12", ".key", ".keystore", ".jks", ".ppk",
                           ".kdbx", ".kdb", ".p8", ".asc", ".gpg", ".der")
# 名字变体：`.env.local`、`.env-prod`、`id_rsa (1)`、`id_rsa.bak`、`credentials.json`。
# 精确匹配挡不住这些 —— 而浏览器下载重名（`id_rsa (1)`）和手工备份（`id_rsa.bak`）
# 恰恰最常出现在桌面/下载目录，也就是读白名单默认放行的那两个目录里。
#
# 只在词干后面紧跟**分隔符**时才算命中，不是裸前缀匹配：`.environment.md`
# 是一份普通文档，把它判成密钥会连带取消它的快照覆盖。
SENSITIVE_NAME_STEMS = (".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                        "credentials", "secrets")
_STEM_SEPARATORS = ".-_ ()"

# 目录级判据。上面那份清单只看 `path.name`，于是 `~/.ssh/config`、`~/.gnupg/*`、
# `~/.kube/config` 这类"文件名本身很普通、所在目录才是要害"的目标一条都命中不了。
# 这一份**不参与快照判定**（快照只关心"要不要备份这个文件"），只给读写闸门用：
# 一份为备份策略写的清单同时兼职三种权限判据，是口径漂移的来源。
SENSITIVE_DIR_SEGMENTS = {".ssh", ".gnupg", ".aws", ".kube", ".azure", ".ace",
                          ".docker", ".gcloud", ".config/gh"}


def is_sensitive_file(path: Path) -> bool:
    """判断某个文件是否属于"不进快照"的密钥类文件（按文件名，不看内容）。

    按名字判定而不是按内容嗅探：嗅探会漏（自定义格式）也会误伤（讲密钥的文档），
    而这份清单命中的都是行业约定俗成的密钥载体。

    注意判错的两个方向**代价不对称，且随调用方而变**：在快照里误判成敏感只损失
    该文件的回滚覆盖；但同一个函数还被读闸门当作"硬拒"判据（`_approve_read_outside`），
    那一侧漏判等于把凭据静默送进模型上下文。所以宁可宽一点。
    """
    # 尾部空格与点：Win32 打开文件时会剥掉它们，`".env "` 实际读到的是 `.env`。
    # 不指望 resolve() 帮忙规范化 —— 它在文件被占用/权限不足时会退回纯词法处理。
    name = path.name.rstrip(" .")
    lower = name.lower()
    if name in SENSITIVE_FILE_NAMES or lower in SENSITIVE_FILE_NAMES:
        return True
    if lower.endswith(SENSITIVE_FILE_SUFFIXES):
        return True
    for stem in SENSITIVE_NAME_STEMS:
        if lower.startswith(stem) and (len(lower) == len(stem)
                                       or lower[len(stem)] in _STEM_SEPARATORS):
            return True
    return False


def is_sensitive_location(path: Path) -> bool:
    """路径是否落在凭据类目录内（`~/.ssh/`、`~/.aws/`、`~/.gnupg/` …）。

    与 `is_sensitive_file` 正交：那个看文件名，这个看目录。两者任一命中，
    读闸门硬拒、写闸门硬拒 —— 这些位置不是"问一次就能放行"的地方，
    确认框里的一行路径不足以让人判断 `~/.ssh/authorized_keys` 意味着永久后门。
    """
    try:
        segs = [s.lower().rstrip(" .") for s in Path(path).parts]
    except (OSError, ValueError):
        return False
    for entry in SENSITIVE_DIR_SEGMENTS:
        want = entry.split("/")
        n = len(want)
        for i in range(len(segs) - n + 1):
            if segs[i:i + n] == want:
                return True
    return False


# 签名密钥默认落在**用户主目录**下，而不是项目内。
# 这一条是整个签名机制成立的前提：`.guardian/` 在项目里，模型用相对路径就能写；
# 如果密钥也在项目里，模型读到密钥后可以给伪造的 meta.json 补一份合法签名，
# 签名就退化成一道校验和 —— 只能防意外损坏，防不了伪造。
DEFAULT_SIGNING_KEY_PATH = Path.home() / ".ace" / "snapshot_signing_key"


class SigningKeyResolution(NamedTuple):
    """签名密钥的解析结果

    warning 非空表示"有话必须说给用户听"：要么配了但没生效，要么密钥太弱。
    调用方（CLI 入口）负责打印，Guardian 本身不打印 —— 它不知道自己在什么界面下跑。
    """
    key: Optional[str]
    source: str      # config / env / keyfile / generated / none
    warning: str     # 空串 = 无需告警


def resolve_signing_key(configured: Optional[object] = None, *,
                        key_path: Optional[object] = None,
                        env: Optional[Mapping[str, str]] = None,
                        project_root: Optional[object] = None,
                        auto_generate: bool = True) -> SigningKeyResolution:
    """决定这次运行用哪个快照签名密钥。

    优先级：显式配置 > 环境变量 ACE_SIGNING_KEY > 密钥文件 > 自动生成并持久化。
    与项目里其它三态开关（`ACE_USE_GO_EXECUTOR` 等）保持同一套顺序。

    为什么默认自动生成而不是"没配就不签名"：
    `README.md` 早就把 `signing_key` 写进了配置示例，但主链路从来没往下传（SEC-010），
    于是签名与校验双双静默跳过 —— 写了 HMAC，一次也没生效过。要求用户先配一个
    密钥才拥有的防护，在真实使用中等于不存在。自动生成没有任何配置成本，
    也不改变任何正常功能，唯一代价是首次运行多一个 0600 的文件。

    持久化失败时**返回 None 并告警**，不返回一个只存在于内存里的密钥：
    那样每次启动密钥都不同，上一次会话留下的快照会全部校验失败、无法回滚 ——
    把安全措施变成功能墙，比不签名更糟。
    """
    env = os.environ if env is None else env
    # 配置文件里写 "~/.ace/..." 是很自然的写法，不展开会得到一个名叫 "~" 的目录，
    # 密钥落在项目工作目录旁边 —— 正是这个函数要避免的位置。
    kp = Path(os.path.expanduser(str(key_path))) if key_path else DEFAULT_SIGNING_KEY_PATH

    def _weak(key: str, source: str) -> SigningKeyResolution:
        # 不因为弱就拒绝：用户显式配的东西不该被静默换掉。但要说清楚它有多弱。
        warn = ("" if len(key) >= 16 else
                f"快照签名密钥过短（{len(key)} 字符，来源 {source}），HMAC 强度不足，建议 ≥32 字符随机串")
        return SigningKeyResolution(key, source, warn)

    for source, raw in (("config", configured), ("env", env.get("ACE_SIGNING_KEY"))):
        if raw is None:
            continue
        if not isinstance(raw, str):
            return SigningKeyResolution(
                None, "none",
                f"快照签名密钥（来源 {source}）不是字符串而是 {type(raw).__name__}，已忽略，签名未启用")
        if raw.strip():
            return _weak(raw.strip(), source)

    # 密钥文件在项目内 = 模型可读 = 签名形同虚设。这种配置必须报出来，
    # 而不是照着用 —— 用户会以为自己开了防护。
    if project_root is not None:
        try:
            root = Path(project_root).resolve()
            if kp.resolve() == root or root in kp.resolve().parents:
                return SigningKeyResolution(
                    None, "none",
                    f"快照签名密钥文件位于项目目录内（{kp}），模型可直接读取后伪造签名，已拒绝启用签名")
        except OSError:
            pass

    try:
        if kp.is_file():
            existing = kp.read_text(encoding="utf-8").strip()
            if existing:
                return _weak(existing, "keyfile")
    except OSError as e:
        return SigningKeyResolution(None, "none", f"快照签名密钥文件不可读（{kp}）：{e}，签名未启用")

    if not auto_generate:
        return SigningKeyResolution(
            None, "none", "未配置签名密钥且禁止自动生成：快照元信息可被伪造，回滚结果不可信")

    key = secrets.token_hex(32)
    try:
        kp.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL + 0600 一步到位：先 write_text 再 chmod 会留一个"文件已存在但还是默认权限"的窗口。
        # Windows 上 mode 基本被忽略（没有 POSIX 位），主目录本身的 ACL 是那里的实际边界。
        fd = os.open(str(kp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key.encode("utf-8"))
        finally:
            os.close(fd)
        return SigningKeyResolution(key, "generated", "")
    except FileExistsError:
        # 竞态：另一个进程刚建好。读它的，不要覆盖 —— 覆盖会让对方已签的快照全部作废。
        try:
            existing = kp.read_text(encoding="utf-8").strip()
        except OSError as e:
            return SigningKeyResolution(None, "none", f"快照签名密钥文件不可读（{kp}）：{e}，签名未启用")
        if existing:
            return _weak(existing, "keyfile")
        return SigningKeyResolution(None, "none", f"快照签名密钥文件为空（{kp}），签名未启用")
    except OSError as e:
        return SigningKeyResolution(
            None, "none",
            f"快照签名密钥无法写入（{kp}）：{e}。签名未启用 —— "
            f"若需启用请手动配置 signing_key 或 ACE_SIGNING_KEY")


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
        self.signing_key = signing_key  # 配置后对快照元信息做 HMAC-SHA256 签名
        self.max_snapshots = max_snapshots  # 快照数量硬上限，超出自动清理最旧的
        # 最近一次 rollback 留下的提示（例如"密钥类文件未被恢复"），供调用方回传给用户
        self.last_rollback_notes: List[str] = []
        for d in (self.snap_dir, self.backup_dir):
            d.mkdir(parents=True, exist_ok=True)

    def _sign(self, content: str) -> str:
        """对快照元信息做 HMAC-SHA256 签名（防伪造）"""
        import hmac
        return hmac.new(self.signing_key.encode("utf-8"),
                        content.encode("utf-8"), hashlib.sha256).hexdigest()

    # ---------- 工具 ----------

    def _walk(self) -> Tuple[List[Path], List[Path]]:
        """遍历项目文件树，返回 (可快照文件, 密钥类文件)；排除构建/缓存/自身存储目录"""
        files: List[Path] = []
        sensitive: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.project_root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                (sensitive if is_sensitive_file(p) else files).append(p)
        return files, sensitive

    def _collect_files(self) -> List[Path]:
        """收集需要快照的文件（不含密钥类文件，见 SENSITIVE_FILE_NAMES）

        快照、回滚前的现状备份、回滚时的清空这三处都用它，所以"跳过"是一致的：
        密钥类文件既不被复制，也不被删除。只有口径一致，回滚才不会出现
        "备份里没有、却先把它删了"的净损失。
        """
        return self._walk()[0]

    def _collect_sensitive(self) -> List[Path]:
        """收集密钥类文件（只用于记录哈希，不复制内容）"""
        return self._walk()[1]

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
        files, sensitive = self._walk()
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
            # SEC-014：只记名字、大小和哈希，不留内容。
            # 记下来是为了让回滚时能说清"这几份东西我没有备份、也没有动"。
            "sensitive_excluded": {},
        }
        for src in sensitive:
            rel = src.relative_to(self.project_root)
            try:
                meta["sensitive_excluded"][rel.as_posix()] = {
                    "size": src.stat().st_size,
                    "sha256": self._sha256(src),
                }
            except OSError:
                # 读不到就跳过：这里只是登记，读失败不该让整个快照失败
                continue
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
                # 常见成因不是攻击，而是这份快照建于签名启用之前。两者在数据上无法区分，
                # 所以只能一律拒绝（否则"删掉 .sig"就是绕过签名的办法），但要把话说清楚，
                # 免得用户以为是 bug。
                return False, ("快照缺少签名文件（当前开启签名校验）；"
                               "若该快照建于启用签名之前，请删除后重新创建")
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

    def sensitive_drift(self, snap_id: str) -> List[str]:
        """列出快照登记过、但现在内容已不同（或已消失）的密钥类文件。

        SEC-014 的配套：这些文件的内容不在快照里，回滚也就恢复不了。
        不备份可以，静默丢失不行 —— 所以至少要能指着名字说"这份需要你自己处理"。
        """
        meta_path = self.snap_dir / snap_id / "meta.json"
        if not meta_path.exists():
            return []
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        drift: List[str] = []
        for rel, info in (meta.get("sensitive_excluded") or {}).items():
            fp = self.project_root / rel
            if not fp.exists():
                drift.append(f"{rel}（快照后已删除，未备份内容）")
                continue
            try:
                if self._sha256(fp) != info.get("sha256"):
                    drift.append(f"{rel}（快照后内容已变化，未备份内容）")
            except OSError:
                drift.append(f"{rel}（无法读取以比对）")
        return drift

    # ---------- 回滚 ----------

    def rollback(self, snap_id: str) -> bool:
        """回滚到指定快照：预检 → 备份当前状态 → 恢复 → 验证 → 清理备份

        `last_rollback_notes` 里会留下"密钥类文件未被恢复"之类的提示，供调用方回传。
        """
        # 1. 完整性预检
        ok, reason = self.verify_snapshot(snap_id)
        if not ok:
            raise SnapshotError(f"回滚前完整性预检失败: {reason}")
        self.last_rollback_notes = [
            f"未回滚（快照不保存其内容）: {d}" for d in self.sensitive_drift(snap_id)]
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
                        # 让"这份快照没包含几个密钥类文件"在 /snapshots 里就能看见
                        "sensitive_excluded": len(meta.get("sensitive_excluded") or {}),
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
