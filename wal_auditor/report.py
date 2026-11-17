"""Human-readable and machine-readable report renderers."""

from __future__ import annotations

import json

from .auditor import AuditReport


def format_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def format_text(report: AuditReport) -> str:
    lines: list[str] = []
    add = lines.append

    add("SQLite WAL 取证审计报告")
    add("=" * 24)
    add(f"文件: {report.file_path}")
    add(f"文件大小: {report.file_size} 字节")
    add(
        "WAL-index (shm): "
        + (
            f"存在 {report.wal_index_path}"
            if report.wal_index_present
            else f"缺失 {report.wal_index_path}（审计不依赖 shm，直接扫描 WAL）"
        )
    )
    add(
        f"段(WAL header)数量: {len(report.segments)}  "
        f"帧总数: {report.frame_count}  "
        f"可见有效帧: {report.valid_frame_count}  "
        f"截断: {'是' if report.truncated else '否'}"
    )
    add("")

    add("[ WAL 段 / header ]")
    if not report.segments:
        add("  未发现任何有效 WAL header。")
    for segment in report.segments:
        add(
            "  段 {segment_index}: offset={offset} page_size={page_size} "
            "ckpt_seq={checkpoint_seq} salt={salt} big_endian={big_endian} "
            "header_checksum={ok}".format(
                ok="OK" if segment["header_checksum_valid"] else "BAD",
                **segment,
            )
        )
    add("")

    add("[ 可见版本（每个有效 commit frame 一个快照）]")
    if not report.visible_versions:
        add("  没有任何有效提交点。")
    for version in report.visible_versions:
        add(
            f"  v{version.version}: frame {version.frame_index} "
            f"(段{version.segment_index}, 段内帧号{version.frame_number}, "
            f"offset {version.header_offset}) commit 页面={version.page_number} "
            f"db_size={version.db_size} 快照页面数={version.pages_visible}"
        )
    add("")

    add("[ 最后一次完整提交点 ]")
    if report.last_commit_frame is None:
        add("  无。所有帧都不能构成已提交快照。")
    else:
        add(
            f"  frame {report.last_commit_frame} @ byte "
            f"{report.last_commit_offset}"
        )
    if report.uncommitted_tail:
        add(
            "  未提交尾部帧（页面存在但不属于任何快照，不得当作有效历史）: "
            + ", ".join(str(index) for index in report.uncommitted_tail)
        )
    add("")

    add("[ 页面覆盖 / 复用时间线 ]")
    if not report.page_histories:
        add("  无可见页面写入。")
    for history in report.page_histories:
        add(
            f"  页面 {history.page_number}: 写入 {history.write_count} 次 "
            f"(首见 frame {history.first_seen_frame}, 末次 frame "
            f"{history.last_written_frame}), "
            f"最终快照可见={history.visible_in_last_commit}"
        )
        for overwrite in history.overwrites:
            add(
                f"    -> frame {overwrite.frame_index} @ byte "
                f"{overwrite.header_offset} 覆盖 frame "
                f"{overwrite.overwrote_frame_index} 的旧版本"
                + (" [该覆盖帧为 commit]" if overwrite.is_commit else "")
            )
    add("")

    add("[ 孤立帧（不可作为证据）]")
    if not report.orphan_frames:
        add("  无。")
    for orphan in report.orphan_frames:
        add(
            f"  frame {orphan.frame_index} @ byte {orphan.header_offset} "
            f"(页面 {orphan.page_number}, 段 {orphan.segment_index}): "
            + ", ".join(orphan.reasons)
        )
    add("")

    add("[ 校验失败位置 ]")
    if not report.checksum_failures:
        add("  无。")
    for failure in report.checksum_failures:
        add(
            f"  frame {failure['frame_index']} @ byte "
            f"{failure['header_offset']} (页面 {failure['page_number']}): "
            f"stored={failure['stored_checksum']} "
            f"computed={failure['computed_checksum']} "
            f"chain_alive={failure['chain_alive']}"
        )
    add("")

    add("[ salt 不匹配（陈旧帧）]")
    if not report.salt_failures:
        add("  无。")
    for failure in report.salt_failures:
        add(
            f"  frame {failure['frame_index']} @ byte "
            f"{failure['header_offset']} (页面 {failure['page_number']}): "
            f"frame_salt={failure['frame_salt']} vs "
            f"header_salt={failure['header_salt']}"
        )
    add("")

    add("[ checkpoint / 并发痕迹与页面大小变化 ]")
    if not report.checkpoint_traces and not report.page_size_changes:
        add("  未检测到额外 WAL header 或页面大小变化。")
    for trace in report.checkpoint_traces:
        add(f"  {trace.kind} @ 段{trace.segment_index} byte {trace.offset}")
        add(f"    {trace.message}")
    for change in report.page_size_changes:
        add(
            "  page_size_change @ 段{segment_index} byte {offset}: "
            "{previous_page_size} -> {current_page_size}".format(**change)
        )
    add("")

    add("[ 解析异常（截断等）]")
    if not report.anomalies:
        add("  无。")
    for anomaly in report.anomalies:
        add(f"  {anomaly.kind} @ byte {anomaly.offset}: {anomaly.message}")
    add("")

    add(
        "取证提示: 本报告重建的是 WAL 页面版本，不是 SQL 行记录；"
        "未提交或校验失败的页面图像不等于有效数据库历史。"
    )
    return "\n".join(lines)
