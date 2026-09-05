#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.skill_tools —— 文件式技能库（借鉴 DSH skill 体系 C1/C2 的务实版）

G:\\AI_skils 这类技能集合：每个技能一个目录，内含 SKILL.md（frontmatter:
name/description + 正文 instructions）。ACE 把它们变成：
- skill_list：列出可用技能（目录注入——模型知道有哪些，不塞正文）
- skill_load：按需加载某个技能的完整正文（模型/用户需要时才注入，不占常驻预算）

与 ai_code.py 内置 SKILLS（简单预设）的关系：这是**文件式扩展**——内置预设
是写死的 5 个，这里扫描外部目录，数量随意、内容随目录走。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.result import ExecutionResult

_SKILL_MAX_BYTES = 64 * 1024    # 单个技能正文上限
_SKILL_MAX_LIST = 200           # 技能数量上限（防巨型目录拖慢）
_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


class SkillLoader:
    """扫描技能目录，解析 SKILL.md 的 frontmatter 与正文。"""

    def __init__(self, skills_dir: str) -> None:
        self.root = Path(skills_dir).expanduser().resolve()

    def _skill_paths(self) -> List[Path]:
        if not self.root.is_dir():
            return []
        out: List[Path] = []
        for d in sorted(self.root.iterdir()):
            if not d.is_dir():
                continue
            f = d / "SKILL.md"
            if f.is_file() and f.stat().st_size <= _SKILL_MAX_BYTES:
                out.append(f)
                if len(out) >= _SKILL_MAX_LIST:
                    break
        return out

    @staticmethod
    def parse(f: Path) -> Optional[Dict[str, str]]:
        """解析 SKILL.md：frontmatter（name/description）+ 正文。格式不合规返回 None。"""
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        if not text.strip():
            return None
        m = _FM_RE.match(text)
        if not m:
            return None
        fm = m.group(1)
        body = text[m.end():].strip()
        name = re.search(r"^name:\s*(.+)$", fm, re.M)
        desc = re.search(r"^description:\s*(.+)$", fm, re.M)
        if not name:
            return None
        return {
            "name": name.group(1).strip(),
            "description": (desc.group(1).strip() if desc else "")[:500],
            "body": body,
            "path": str(f),
        }

    def list_skills(self) -> List[Dict[str, str]]:
        out = []
        for f in self._skill_paths():
            parsed = self.parse(f)
            if parsed:
                out.append({"name": parsed["name"], "description": parsed["description"]})
        return out

    def load(self, name: str) -> Optional[Dict[str, str]]:
        for f in self._skill_paths():
            parsed = self.parse(f)
            if parsed and parsed["name"].lower() == name.strip().lower():
                return parsed
        return None


class SkillTools:
    def _skill_loader(self) -> Optional[SkillLoader]:
        """技能目录：config skills_dir（--skills）；None = 未配置则用内置预设。"""
        d = getattr(self, "skills_dir", None)
        if not d:
            return None
        if getattr(self, "_skill_loader_obj", None) is None:
            self._skill_loader_obj = SkillLoader(d)
        return self._skill_loader_obj

    def _exec_skill_list(self, params: Dict) -> ExecutionResult:
        loader = self._skill_loader()
        if loader is None:
            return ExecutionResult(status="error", error_code="400",
                                   message="未配置技能目录（--skills <目录> 指定）")
        skills = loader.list_skills()
        if not skills:
            return ExecutionResult(status="success", data={
                "skills": [], "root": str(loader.root),
                "hint": f"技能目录 {loader.root} 没有可用的 SKILL.md"})
        lines = [f"{s['name']}: {s['description']}" for s in skills]
        return ExecutionResult(status="success", data={
            "skills": skills, "count": len(skills), "root": str(loader.root),
            "content": "\n".join(lines),
            "hint": "技能正文按需加载：skill_load <技能名> 注入完整 instructions",
        })

    def _exec_skill_load(self, params: Dict) -> ExecutionResult:
        loader = self._skill_loader()
        if loader is None:
            return ExecutionResult(status="error", error_code="400",
                                   message="未配置技能目录（--skills <目录> 指定）")
        name = str(params.get("name", "")).strip()
        if not name:
            return ExecutionResult(status="error", error_code="400",
                                   message="skill_load 需要 name 参数（技能名，skill_list 查看）")
        skill = loader.load(name)
        if skill is None:
            return ExecutionResult(status="error", error_code="404",
                                   message=f"技能不存在: {name}（skill_list 查看可用技能）")
        body = skill["body"][:_SKILL_MAX_BYTES]
        return ExecutionResult(status="success", data={
            "name": skill["name"], "description": skill["description"],
            "content": f"<skill_content name={skill['name']}>\n{body}\n</skill_content>",
            "hint": "以上是技能的完整 instructions，请遵循其中的规则完成相关任务",
        })
