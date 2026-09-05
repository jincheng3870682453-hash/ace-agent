#!/usr/bin/env python3
"""
download_model.py —— 下载 Qwen2.5-VL-3B GGUF 模型
用法:
  python download_model.py          # 下载到 ./models/
  python download_model.py /path    # 下载到指定目录
"""
import sys
import urllib.request
from pathlib import Path

MODELS = {
    "qwen2.5-vl-3b-q4_k_m.gguf": {
        "desc": "Qwen2.5-VL-3B-Instruct 主模型 (Q4_K_M 量化, ~1.8GB)",
        "urls": [
            "https://www.modelscope.cn/models/huihui-ai/Qwen2.5-VL-3B-Instruct-abliterated/resolve/master/GGUF/ggml-model-Q4_K_M.gguf",
            "https://hf-mirror.com/huihui-ai/Qwen2.5-VL-3B-Instruct-abliterated/resolve/main/GGUF/ggml-model-Q4_K_M.gguf",
        ]
    },
    "qwen2.5-vl-3b-mmproj.gguf": {
        "desc": "视觉投影模型 (mmproj, ~600MB)",
        "urls": [
            "https://www.modelscope.cn/models/huihui-ai/Qwen2.5-VL-3B-Instruct-abliterated/resolve/master/GGUF/mmproj-ggml-model-f16.gguf",
            "https://hf-mirror.com/huihui-ai/Qwen2.5-VL-3B-Instruct-abliterated/resolve/main/GGUF/mmproj-ggml-model-f16.gguf",
        ]
    }
}

def download(name, info, out_dir: Path):
    target = out_dir / name
    if target.exists():
        print(f"✓ {name} 已存在，跳过")
        return True

    print(f"↓ 正在下载 {name}...")
    print(f"  {info['desc']}")

    for url in info["urls"]:
        try:
            print(f"  尝试: {url[:60]}...")
            urllib.request.urlretrieve(url, target)
            size = target.stat().st_size / (1024**3)
            print(f"  ✓ 完成 ({size:.2f} GB)")
            return True
        except Exception as e:
            print(f"  ✗ 失败: {e}")
            if target.exists():
                target.unlink()
    return False

def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("models")
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 50)
    print("ACE Agent VLM 模型下载器")
    print("=" * 50)

    ok = True
    for name, info in MODELS.items():
        if not download(name, info, out_dir):
            ok = False

    print()
    if ok:
        print("🎉 全部下载完成！")
        print(f"模型目录: {out_dir.absolute()}")
        print("\n启动命令:")
        print("  docker compose up ace-standard")
    else:
        print("❌ 部分下载失败，请检查网络或手动下载")
        sys.exit(1)

if __name__ == "__main__":
    main()
