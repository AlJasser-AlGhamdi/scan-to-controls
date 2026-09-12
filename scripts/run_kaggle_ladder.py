#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL_DIR = ROOT / "evaluation" / "kaggle_kernel"
DATA = ROOT / "evaluation" / "kaggle_baseline_data.json"
BUILD = pathlib.Path("build/kaggle_build")
KAGGLE = str(pathlib.Path.home() / ".local" / "bin" / "kaggle")
ARABIC = re.compile(r"[؀-ۿݐ-ݿ]")


def build() -> None:
    data_bytes = DATA.read_bytes()
    if ARABIC.search(data_bytes.decode("utf-8")):
        raise SystemExit("ARABIC in kaggle_baseline_data.json: copyright stop, refusing to build")
    template = (KERNEL_DIR / "kaggle_run.py").read_text(encoding="utf-8")
    b64 = base64.b64encode(data_bytes).decode()
    filled = template.replace("__DATA_B64__", b64)
    BUILD.mkdir(parents=True, exist_ok=True)
    (BUILD / "kaggle_run.py").write_text(filled, encoding="utf-8")
    shutil.copy(KERNEL_DIR / "kernel-metadata.json", BUILD / "kernel-metadata.json")
    meta = json.loads((BUILD / "kernel-metadata.json").read_text())
    print(f"built {BUILD}/kaggle_run.py ({len(filled)} chars); id={meta['id']} private={meta['is_private']} "
          f"gpu={meta['enable_gpu']} internet={meta['enable_internet']}; data zero-Arabic verified")


def push() -> None:
    subprocess.run([KAGGLE, "kernels", "push", "-p", str(BUILD)], check=True)


def status() -> None:
    meta = json.loads((KERNEL_DIR / "kernel-metadata.json").read_text())
    subprocess.run([KAGGLE, "kernels", "status", meta["id"]], check=False)


def fetch(dest: str) -> None:
    meta = json.loads((KERNEL_DIR / "kernel-metadata.json").read_text())
    pathlib.Path(dest).mkdir(parents=True, exist_ok=True)
    subprocess.run([KAGGLE, "kernels", "output", meta["id"], "-p", dest], check=True)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"
    if cmd == "build":
        build()
    elif cmd == "push":
        push()
    elif cmd == "status":
        status()
    elif cmd == "fetch":
        fetch(sys.argv[2])
    else:
        raise SystemExit(f"unknown command {cmd}")
