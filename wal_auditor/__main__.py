"""Command line entry point: ``python -m wal_auditor example.db-wal``."""

from __future__ import annotations

import argparse
import sys

from .auditor import audit_wal
from .report import format_json, format_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "解析 SQLite WAL，按 commit frame 重建可见页面版本，"
            "输出覆盖时间线、提交点、孤立帧和校验失败。"
        )
    )
    parser.add_argument("wal_path", help="WAL 文件路径，例如 app.db-wal")
    parser.add_argument(
        "--shm",
        dest="shm_path",
        default=None,
        help="可选的 WAL-index (-shm) 路径；默认使用 <wal>-shm",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="输出 JSON 而非文本报告",
    )
    args = parser.parse_args(argv)

    report = audit_wal(args.wal_path, args.shm_path)
    print(format_json(report) if args.as_json else format_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
