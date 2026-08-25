"""Docker 一次性容器执行层 —— 把命令执行真正关进内核边界。

## 为什么需要这一层

在这之前，ace 的"沙箱"全部是进程内的 Python 层策略：AST 黑名单、路径包含
检查、危险命令正则。`terminal_exec` 是 `subprocess.run(cmd, shell=True)`，
cwd 固定在项目根 —— 但 `shell=True` 下 `cd /` 或写绝对路径随便走，cwd 不是
边界。tools/file_tools.py 的注释自己承认过这件事：黑名单是止血层，真正的
隔离依赖容器或低权限账户。这个模块就是把那句注释兑现。

## 边界在哪

容器提供的是 Python 层拿不到的东西：

- `--network none`：没有网卡，凭据无法外传，也下载不了第二阶段载荷
- `--memory` / `--pids-limit`：fork bomb 和内存耗尽变成容器自己的事
- `--read-only` + `--tmpfs /tmp`：根文件系统不可写，只有挂进来的工作目录可写
- `--cap-drop ALL` + `--security-opt no-new-privileges`：拿不到额外权能
- `--rm`：进程树、临时文件、残留状态随容器一起消失

容器不提供的：内核共享。容器逃逸漏洞仍然是逃逸。要更强的边界得上虚拟机。

## 一个刻意的设计：不做静默回退

启用了 docker 沙箱但 docker 不可用时，这里返回失败，**不会**偷偷改回宿主
执行。静默回退比没有沙箱更危险——用户以为命令跑在容器里，实际跑在自己机器
上，而且没有任何提示。宁可报错让人去修 docker。

纯标准库实现（subprocess 调 docker CLI），不引入 docker-py。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_IMAGE = "ace-sandbox:latest"
DEFAULT_TIMEOUT = 30
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS = 128
DEFAULT_TMPFS_SIZE = "64m"

# docker daemon 探测的超时。探测本身要快——它挡在每次工具调用前面，
# 不能因为 daemon 卡住就让整个 agent 跟着卡 30 秒。
PROBE_TIMEOUT = 8


class DockerUnavailable(RuntimeError):
    """docker CLI 缺失或 daemon 不可达。调用方应把它变成明确的错误码，不要回退宿主。"""


class DockerSandbox:
    """把单条命令 / 单段代码丢进一次性容器执行。

    workspace 是唯一挂进容器的宿主路径（挂到 /work，容器内 cwd）。
    项目目录之外的东西容器里看不见——这是"隔离"的字面含义。
    """

    def __init__(self, workspace: str, image: str = DEFAULT_IMAGE,
                 timeout: int = DEFAULT_TIMEOUT, memory: str = DEFAULT_MEMORY,
                 cpus: str = DEFAULT_CPUS, pids_limit: int = DEFAULT_PIDS,
                 network: str = "none") -> None:
        self.workspace = Path(workspace).resolve()
        self.image = image
        self.timeout = int(timeout)
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = int(pids_limit)
        self.network = network
        self._available: Optional[bool] = None   # 探测结果缓存
        self._image_ok: Optional[bool] = None    # 镜像存在性缓存（与探测同理，挡在每条命令前）
        self._detail = ""


    # ---------- 可用性 ----------

    def probe(self, force: bool = False) -> bool:
        """docker CLI 在 PATH 且 daemon 应答。结果缓存，避免每条命令都探一次。"""
        if self._available is not None and not force:
            return self._available
        if not shutil.which("docker"):
            self._available, self._detail = False, "PATH 里没有 docker 命令"
            return False
        try:
            r = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT,
                stdin=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, OSError) as e:
            self._available, self._detail = False, f"docker 探测失败: {e}"
            return False
        if r.returncode != 0:
            # 最典型的情况：Docker Desktop 没启动，daemon 连不上
            self._available = False
            self._detail = (r.stderr or r.stdout or "").strip()[:200] or "daemon 不可达"
            return False
        self._available, self._detail = True, f"docker server {r.stdout.strip()}"
        return True

    @property
    def detail(self) -> str:
        """最近一次探测的说明，用于把失败原因原样告诉用户。"""
        return self._detail

    def image_present(self, force: bool = False) -> bool:
        """沙箱镜像在本地。结果缓存，理由和 probe 一样：它挡在每条命令前面。"""
        if self._image_ok is not None and not force:
            return self._image_ok
        try:
            r = subprocess.run(["docker", "image", "inspect", self.image],
                               capture_output=True, text=True,
                               timeout=PROBE_TIMEOUT, stdin=subprocess.DEVNULL)
            self._image_ok = (r.returncode == 0)
        except (subprocess.TimeoutExpired, OSError):
            self._image_ok = False
        return self._image_ok

    def _ensure_ready(self) -> None:
        """跑之前把"能不能跑"问清楚，不能跑就抛 DockerUnavailable（调用方会转成 503）。

        镜像缺失单独判一次，而不是让 `docker run` 自己去撞，原因是撞出来的错不对：
        本地找不到 `ace-sandbox:latest` 时 docker 会先当它是远端镜像去 registry 拉，
        于是用户等一个网络超时，然后拿到一句 "pull access denied / not found" ——
        听起来像是仓库配错了或者要登录，而真正要做的只是本地 build 一次。

        这个镜像是故意不发布到 registry 的：它是执行边界，内容得由部署方自己掌握。
        所以"拉不到"不是故障，是**本来就要你构建**。
        """
        if not self.probe():
            raise DockerUnavailable(self._detail)
        if not self.image_present():
            raise DockerUnavailable(
                f"本地没有沙箱镜像 {self.image}（它不发布到 registry，需要自己构建）：\n"
                f"    docker build -t {self.image} -f docker/Dockerfile.sandbox .\n"
                "已有镜像可用 --sandbox-image 指定；不想要容器边界就用 --sandbox off。")

    # ---------- 执行 ----------

    def _base_args(self, name: str) -> List[str]:
        args = [
            "docker", "run", "--rm", "-i",
            "--name", name,
            f"--network={self.network}",
            f"--memory={self.memory}",
            # memory-swap 等于 memory 才算真的封住内存：否则超额部分会换到 swap
            f"--memory-swap={self.memory}",
            f"--cpus={self.cpus}",
            f"--pids-limit={self.pids_limit}",
            "--read-only",
            f"--tmpfs=/tmp:rw,nosuid,nodev,size={DEFAULT_TMPFS_SIZE}",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "-v", f"{self.workspace}:/work:rw",
            "-w", "/work",
        ]
        # POSIX 上用调用者的 uid/gid，容器写出来的文件在宿主侧归属正确，
        # 不会留下一堆 root 拥有的产物。Windows 上没有 uid 概念，
        # 交给镜像里的 USER（见 docker/Dockerfile.sandbox）。
        if os.name != "nt" and hasattr(os, "getuid"):
            args += ["-u", f"{os.getuid()}:{os.getgid()}"]
        return args

    def _run(self, args: List[str], name: str,
             stdin_data: Optional[str] = None) -> Dict:
        try:
            r = subprocess.run(
                args, capture_output=True, text=True, timeout=self.timeout,
                input=stdin_data if stdin_data is not None else "",
                encoding="utf-8", errors="replace")
            return {"stdout": r.stdout, "stderr": r.stderr,
                    "returncode": r.returncode, "timeout": False}
        except subprocess.TimeoutExpired:
            # subprocess 超时只杀掉 docker 客户端，容器还在跑。必须显式清掉，
            # 否则超时一次就漏一个吃着 CPU 的容器。
            self._force_remove(name)
            return {"stdout": "", "stderr": f"容器执行超时（{self.timeout} 秒），已强制清理",
                    "returncode": 124, "timeout": True}

    @staticmethod
    def _force_remove(name: str) -> None:
        try:
            subprocess.run(["docker", "rm", "-f", name],
                           capture_output=True, timeout=PROBE_TIMEOUT,
                           stdin=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def run_shell(self, command: str) -> Dict:
        """在容器里跑一条 shell 命令。命令原文经 argv 传给 sh -c，不经宿主 shell。"""
        self._ensure_ready()
        name = f"ace-sbx-{uuid.uuid4().hex[:10]}"
        args = self._base_args(name) + [self.image, "sh", "-c", command]
        return self._run(args, name)

    def run_python(self, code: str) -> Dict:
        """在容器里跑一段 Python。代码经 stdin 喂给 `python -`，不落宿主磁盘。"""
        self._ensure_ready()
        name = f"ace-sbx-{uuid.uuid4().hex[:10]}"
        args = self._base_args(name) + [
            "-e", "PYTHONIOENCODING=utf-8",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            self.image, "python", "-",
        ]
        return self._run(args, name, stdin_data=code)


def build_sandbox(config: Optional[Dict], workspace: str) -> Optional[DockerSandbox]:
    """按配置造沙箱；未启用返回 None。

    config 形如 {"mode": "docker", "image": ..., "timeout": ..., ...}。
    mode 不是 "docker" 就当没启用——保持默认关闭，不给现有用户变行为。
    """
    cfg = config or {}
    if str(cfg.get("mode", "off")).lower() != "docker":
        return None
    return DockerSandbox(
        workspace=workspace,
        image=cfg.get("image") or DEFAULT_IMAGE,
        timeout=int(cfg.get("timeout") or DEFAULT_TIMEOUT),
        memory=cfg.get("memory") or DEFAULT_MEMORY,
        cpus=str(cfg.get("cpus") or DEFAULT_CPUS),
        pids_limit=int(cfg.get("pids_limit") or DEFAULT_PIDS),
        network=cfg.get("network") or "none",
    )
