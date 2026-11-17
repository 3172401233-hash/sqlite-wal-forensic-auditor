"""Forensic reconstruction of WAL visibility semantics.

The auditor turns the raw parse result into an evidence model that mirrors
how SQLite actually reads a WAL file:

* A frame belongs to the WAL segment (header) under which it appears.
* Frames whose salt differs from the segment header are stale leftovers
  from an older WAL incarnation and are never visible.
* Frames participate in the cumulative checksum chain; once the chain is
  broken, no later frame can be validated.
* Only frames up to and including a valid commit frame form a readable
  database snapshot; everything after the last commit is an uncommitted
  tail.

Important forensic caveat: the model reconstructs *page versions*, not SQL
rows. A page image says nothing on its own about whether a row was ever
committed at the SQL level.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .parser import (
    ParseAnomaly,
    ParsedFrame,
    ParsedHeader,
    parse_wal,
)


@dataclass
class OrphanFrame:
    frame_index: int
    segment_index: int
    page_number: int
    header_offset: int
    reasons: list[str]


@dataclass
class VisibleVersion:
    """One readable snapshot, produced by each valid commit frame."""

    version: int
    frame_index: int
    segment_index: int
    frame_number: int
    page_number: int
    db_size: int
    header_offset: int
    pages_changed: int
    pages_visible: int


@dataclass
class PageOverwrite:
    page_number: int
    segment_index: int
    frame_index: int
    frame_number: int
    header_offset: int
    overwrote_frame_index: int
    is_commit: bool


@dataclass
class PageHistory:
    page_number: int
    first_seen_frame: int
    last_written_frame: int
    write_count: int
    overwrites: list[PageOverwrite]
    visible_in_last_commit: bool


@dataclass
class CheckpointTrace:
    kind: str
    segment_index: int
    offset: int
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class AuditReport:
    file_path: str
    file_size: int
    wal_index_path: str | None
    wal_index_present: bool
    segments: list[dict]
    frame_count: int
    valid_frame_count: int
    visible_versions: list[VisibleVersion]
    last_commit_frame: int | None
    last_commit_offset: int | None
    uncommitted_tail: list[int]
    orphan_frames: list[OrphanFrame]
    checksum_failures: list[dict]
    salt_failures: list[dict]
    page_histories: list[PageHistory]
    anomalies: list[ParseAnomaly]
    checkpoint_traces: list[CheckpointTrace]
    page_size_changes: list[dict]
    truncated: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _is_visible_frame(frame: ParsedFrame) -> bool:
    return (
        not frame.truncated
        and frame.chain_alive
        and frame.checksum_valid is True
        and frame.salt_matches_header
        and frame.page_number > 0
    )


def audit_wal(wal_path: str | Path,
              wal_index_path: str | Path | None = None) -> AuditReport:
    """Audit a WAL file and return the full evidence report."""
    path = Path(wal_path)
    data = path.read_bytes()
    headers, frames, anomalies = parse_wal(data)
    return build_report(
        data=data,
        headers=headers,
        frames=frames,
        anomalies=anomalies,
        file_path=str(path),
        wal_index_path=(
            str(wal_index_path) if wal_index_path is not None
            else str(path) + "-shm"
        ),
    )


def build_report(data: bytes, headers: list[ParsedHeader],
                 frames: list[ParsedFrame],
                 anomalies: list[ParseAnomaly],
                 file_path: str,
                 wal_index_path: str) -> AuditReport:
    """Assemble an audit report from parsed structures (test friendly)."""

    segments = [
        {
            "segment_index": header.segment_index,
            "offset": header.offset,
            "page_size": header.page_size,
            "checkpoint_seq": header.checkpoint_seq,
            "salt": [header.salt_1, header.salt_2],
            "big_endian": header.big_endian,
            "header_checksum_valid": header.checksum_valid,
        }
        for header in headers
    ]

    checksum_failures = [
        {
            "frame_index": frame.index,
            "segment_index": frame.segment_index,
            "frame_number": frame.frame_number,
            "header_offset": frame.header_offset,
            "page_number": frame.page_number,
            "stored_checksum": list(frame.stored_checksum),
            "computed_checksum": (
                list(frame.computed_checksum)
                if frame.computed_checksum is not None else None
            ),
            "chain_alive": frame.chain_alive,
        }
        for frame in frames
        if not frame.truncated and frame.checksum_valid is False
    ]

    salt_failures = [
        {
            "frame_index": frame.index,
            "segment_index": frame.segment_index,
            "frame_number": frame.frame_number,
            "header_offset": frame.header_offset,
            "page_number": frame.page_number,
            "frame_salt": [frame.salt_1, frame.salt_2],
            "header_salt": list(headers[frame.segment_index].salt)
            if frame.segment_index < len(headers) else None,
        }
        for frame in frames
        if not frame.salt_matches_header
    ]

    orphan_frames: list[OrphanFrame] = []
    visible_versions: list[VisibleVersion] = []
    uncommitted_tail: list[int] = []

    # Per-segment bookkeeping used to reconstruct snapshots.
    last_commit_index: dict[int, int] = {}
    # frame index -> set of pages written by that frame's segment up to it.
    snapshot_pages: dict[int, dict[int, int]] = {}
    # Running page -> frame map for the segment currently being walked.
    segment_pages: dict[int, dict[int, int]] = {}

    last_commit_overall: int | None = None

    for frame in frames:
        visible = _is_visible_frame(frame)

        if not visible:
            reasons: list[str] = []
            if frame.truncated:
                reasons.append("truncated_frame")
            if not frame.salt_matches_header:
                reasons.append("stale_salt")
            if not frame.chain_alive and not frame.truncated:
                reasons.append("checksum_chain_broken")
            if (
                not frame.truncated
                and frame.chain_alive
                and frame.checksum_valid is False
            ):
                reasons.append("checksum_mismatch")
            if frame.page_number == 0:
                reasons.append("invalid_page_number_zero")
            if reasons:
                orphan_frames.append(OrphanFrame(
                    frame_index=frame.index,
                    segment_index=frame.segment_index,
                    page_number=frame.page_number,
                    header_offset=frame.header_offset,
                    reasons=reasons,
                ))
            continue

        seg = frame.segment_index
        pages = segment_pages.setdefault(seg, {})
        pages[frame.page_number] = frame.index
        snapshot_pages[frame.index] = pages

        if frame.is_commit:
            last_commit_index[seg] = frame.index
            last_commit_overall = frame.index
            visible_versions.append(VisibleVersion(
                version=len(visible_versions) + 1,
                frame_index=frame.index,
                segment_index=seg,
                frame_number=frame.frame_number,
                page_number=frame.page_number,
                db_size=frame.db_size,
                header_offset=frame.header_offset,
                pages_changed=1,
                pages_visible=len(pages),
            ))

    # Classify visible frames after the last valid commit as uncommitted.
    for frame in frames:
        if (
            _is_visible_frame(frame)
            and (
                last_commit_overall is None
                or frame.index > last_commit_overall
            )
        ):
            uncommitted_tail.append(frame.index)

    # Page-level timelines and overwrite evidence.
    writes_by_page: dict[int, list[ParsedFrame]] = {}
    for frame in frames:
        if _is_visible_frame(frame):
            writes_by_page.setdefault(frame.page_number, []).append(frame)

    page_histories: list[PageHistory] = []
    for page_number in sorted(writes_by_page):
        writes = writes_by_page[page_number]
        overwrites: list[PageOverwrite] = []
        for previous, current in zip(writes, writes[1:]):
            overwrites.append(PageOverwrite(
                page_number=page_number,
                segment_index=current.segment_index,
                frame_index=current.index,
                frame_number=current.frame_number,
                header_offset=current.header_offset,
                overwrote_frame_index=previous.index,
                is_commit=current.is_commit,
            ))
        last = writes[-1]
        page_histories.append(PageHistory(
            page_number=page_number,
            first_seen_frame=writes[0].index,
            last_written_frame=last.index,
            write_count=len(writes),
            overwrites=overwrites,
            # A page is part of the final snapshot only when its most
            # recent visible write is at or before the last commit.
            visible_in_last_commit=(
                last_commit_overall is not None
                and last.index <= last_commit_overall
            ),
        ))

    checkpoint_traces, page_size_changes = _detect_checkpoint_traces(headers)

    truncated = any(
        anomaly.kind.startswith("truncated") for anomaly in anomalies
    )

    valid_frame_count = sum(1 for frame in frames if _is_visible_frame(frame))

    last_commit_offset = None
    if last_commit_overall is not None:
        last_commit_offset = frames[last_commit_overall].header_offset

    shm_path = Path(wal_index_path)

    return AuditReport(
        file_path=file_path,
        file_size=len(data),
        wal_index_path=str(shm_path),
        wal_index_present=shm_path.exists(),
        segments=segments,
        frame_count=len(frames),
        valid_frame_count=valid_frame_count,
        visible_versions=visible_versions,
        last_commit_frame=last_commit_overall,
        last_commit_offset=last_commit_offset,
        uncommitted_tail=uncommitted_tail,
        orphan_frames=orphan_frames,
        checksum_failures=checksum_failures,
        salt_failures=salt_failures,
        page_histories=page_histories,
        anomalies=anomalies,
        checkpoint_traces=checkpoint_traces,
        page_size_changes=page_size_changes,
        truncated=truncated,
    )


def _detect_checkpoint_traces(
    headers: list[ParsedHeader],
) -> tuple[list[CheckpointTrace], list[dict]]:
    traces: list[CheckpointTrace] = []
    page_size_changes: list[dict] = []
    if not headers:
        return traces, page_size_changes

    seen_salts: dict[tuple[int, int], int] = {}
    first = headers[0]
    seen_salts[first.salt] = first.segment_index

    for header in headers[1:]:
        previous = headers[header.segment_index - 1]

        if header.checkpoint_seq != previous.checkpoint_seq:
            traces.append(CheckpointTrace(
                kind="checkpoint_sequence_advance",
                segment_index=header.segment_index,
                offset=header.offset,
                message=(
                    "WAL header checkpoint sequence changed from "
                    f"{previous.checkpoint_seq} to "
                    f"{header.checkpoint_seq}; a concurrent checkpoint "
                    "restarted the WAL"
                ),
                detail={
                    "previous_seq": previous.checkpoint_seq,
                    "current_seq": header.checkpoint_seq,
                    "previous_salt": list(previous.salt),
                    "current_salt": list(header.salt),
                },
            ))
        else:
            traces.append(CheckpointTrace(
                kind="embedded_wal_header",
                segment_index=header.segment_index,
                offset=header.offset,
                message=(
                    "A second WAL header appears without a checkpoint "
                    "sequence change; WAL reuse/reset evidence"
                ),
                detail={
                    "previous_salt": list(previous.salt),
                    "current_salt": list(header.salt),
                },
            ))

        if header.page_size != previous.page_size:
            page_size_changes.append({
                "segment_index": header.segment_index,
                "offset": header.offset,
                "previous_page_size": previous.page_size,
                "current_page_size": header.page_size,
            })

        if header.salt in seen_salts:
            traces.append(CheckpointTrace(
                kind="duplicate_salt",
                segment_index=header.segment_index,
                offset=header.offset,
                message=(
                    "Salt pair "
                    f"({header.salt_1}, {header.salt_2}) already appeared "
                    f"in segment {seen_salts[header.salt]}; frames cannot be "
                    "distinguished by salt alone"
                ),
                detail={
                    "first_segment_index": seen_salts[header.salt],
                    "salt": list(header.salt),
                },
            ))
        else:
            seen_salts[header.salt] = header.segment_index

    return traces, page_size_changes
