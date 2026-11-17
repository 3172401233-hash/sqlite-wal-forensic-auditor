"""Low-level, interpretation-free WAL byte stream parser.

The parser never decides whether a frame is visible to a reader; it only
walks the byte stream, recovers as many headers and frames as possible and
records every structural problem it encounters. All forensic decisions are
made later by :mod:`wal_auditor.auditor`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .format import (
    FH_CHECKSUM_1,
    FH_CHECKSUM_2,
    FH_DB_SIZE,
    FH_PAGE_NUMBER,
    FH_SALT_1,
    FH_SALT_2,
    FRAME_HEADER_SIZE,
    FRAME_HEADER_STRUCT,
    WAL_HEADER_SIZE,
    WAL_HEADER_STRUCT,
    WAL_MAGICS,
    WH_CHECKSUM_1,
    WH_CHECKSUM_2,
    WH_CHECKPOINT_SEQ,
    WH_FILE_FORMAT,
    WH_MAGIC,
    WH_PAGE_SIZE,
    WH_SALT_1,
    WH_SALT_2,
    frame_checksum,
    header_checksum,
    is_valid_page_size,
)

WAL_FILE_FORMAT = 3007000


@dataclass
class ParseAnomaly:
    """A structural problem found while walking the byte stream."""

    kind: str
    offset: int
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class ParsedHeader:
    """One WAL header; a file may contain several after WAL reset/reuse."""

    segment_index: int
    offset: int
    magic: int
    big_endian: bool
    file_format: int
    page_size: int
    checkpoint_seq: int
    salt_1: int
    salt_2: int
    stored_checksum: tuple[int, int]
    computed_checksum: tuple[int, int]
    checksum_valid: bool
    valid: bool
    error: str | None

    @property
    def salt(self) -> tuple[int, int]:
        return self.salt_1, self.salt_2


@dataclass
class ParsedFrame:
    """One frame header plus enough metadata to validate it later."""

    index: int
    segment_index: int
    frame_number: int
    header_offset: int
    page_offset: int | None
    page_number: int
    db_size: int
    salt_1: int
    salt_2: int
    stored_checksum: tuple[int, int]
    computed_checksum: tuple[int, int] | None
    checksum_valid: bool | None
    salt_matches_header: bool
    is_commit: bool
    truncated: bool
    chain_alive: bool
    raw_header: bytes

    @property
    def salt(self) -> tuple[int, int]:
        return self.salt_1, self.salt_2


def _find_next_magic(data: bytes, start: int) -> int:
    """Return the offset of the next WAL magic value, or -1."""
    best = -1
    for magic in WAL_MAGICS:
        needle = magic.to_bytes(4, "big")
        pos = data.find(needle, start)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
    return best


def _parse_wal_header(data: bytes, offset: int,
                      segment_index: int) -> ParsedHeader | None:
    if len(data) - offset < WAL_HEADER_SIZE:
        return None
    words = WAL_HEADER_STRUCT.unpack_from(data, offset)
    magic = words[WH_MAGIC]
    stored = (words[WH_CHECKSUM_1], words[WH_CHECKSUM_2])
    header_bytes = data[offset:offset + WAL_HEADER_SIZE]
    # The two magic values hint at the native byte order, but real-world
    # writers (e.g. little-endian SQLite builds) can emit the big-endian
    # magic while still computing checksums in little-endian word order.
    # Decide empirically by validating the header checksum both ways.
    be_candidate = header_checksum(header_bytes, True)
    le_candidate = header_checksum(header_bytes, False)
    if stored == be_candidate:
        big_endian = True
        computed = be_candidate
    elif stored == le_candidate:
        big_endian = False
        computed = le_candidate
    else:
        # Fall back to the magic convention; the stored checksum will then
        # be reported as invalid below.
        big_endian = magic == 0x377F0682
        computed = be_candidate if big_endian else le_candidate
    page_size = words[WH_PAGE_SIZE]
    error: str | None = None
    if words[WH_FILE_FORMAT] != WAL_FILE_FORMAT:
        error = (
            f"unsupported WAL file format version "
            f"{words[WH_FILE_FORMAT]} (expected {WAL_FILE_FORMAT})"
        )
    elif not is_valid_page_size(page_size):
        error = f"invalid page size {page_size} in WAL header"
    elif stored != computed:
        error = "WAL header checksum mismatch"

    return ParsedHeader(
        segment_index=segment_index,
        offset=offset,
        magic=magic,
        big_endian=big_endian,
        file_format=words[WH_FILE_FORMAT],
        page_size=page_size,
        checkpoint_seq=words[WH_CHECKPOINT_SEQ],
        salt_1=words[WH_SALT_1],
        salt_2=words[WH_SALT_2],
        stored_checksum=stored,
        computed_checksum=computed,
        checksum_valid=stored == computed,
        valid=error is None,
        error=error,
    )


def parse_wal(data: bytes) -> tuple[list[ParsedHeader], list[ParsedFrame],
                                    list[ParseAnomaly]]:
    """Parse a WAL byte stream into headers, frames and anomalies.

    The scan tolerates truncated tails, embedded WAL headers left behind by
    checkpoints/WAL reuse and stale frames carrying an older salt.
    """
    headers: list[ParsedHeader] = []
    frames: list[ParsedFrame] = []
    anomalies: list[ParseAnomaly] = []

    pos = 0
    file_size = len(data)
    current: ParsedHeader | None = None
    frame_number = 0
    global_index = 0
    checksum_seed: tuple[int, int] | None = None

    while pos < file_size:
        magic_here = (
            file_size - pos >= 4
            and int.from_bytes(data[pos:pos + 4], "big") in WAL_MAGICS
        )

        if magic_here:
            header = _parse_wal_header(data, pos, len(headers))
            if header is None:
                anomalies.append(ParseAnomaly(
                    kind="truncated_wal_header",
                    offset=pos,
                    message=(
                        f"WAL magic at byte {pos} is followed by only "
                        f"{file_size - pos} bytes; 32-byte header required"
                    ),
                ))
                break
            if not header.valid:
                anomalies.append(ParseAnomaly(
                    kind="invalid_wal_header",
                    offset=pos,
                    message=header.error or "invalid WAL header",
                    detail={
                        "page_size": header.page_size,
                        "stored_checksum": list(header.stored_checksum),
                        "computed_checksum": list(header.computed_checksum),
                    },
                ))
                break
            headers.append(header)
            current = header
            frame_number = 0
            checksum_seed = header.stored_checksum
            pos += WAL_HEADER_SIZE
            continue

        if current is None:
            resync = _find_next_magic(data, pos + 1)
            anomalies.append(ParseAnomaly(
                kind="bytes_without_wal_header",
                offset=pos,
                message=(
                    f"{resync - pos if resync != -1 else file_size - pos} "
                    "byte(s) appear before any valid WAL header"
                ),
                detail={"next_magic_offset": resync},
            ))
            if resync == -1:
                break
            pos = resync
            continue

        page_size = current.page_size
        full_frame_size = FRAME_HEADER_SIZE + page_size
        remaining = file_size - pos

        if remaining < FRAME_HEADER_SIZE:
            anomalies.append(ParseAnomaly(
                kind="truncated_frame_header",
                offset=pos,
                message=(
                    f"only {remaining} of {FRAME_HEADER_SIZE} frame-header "
                    f"bytes remain at byte {pos}; WAL chunk was cut mid-write"
                ),
                detail={"expected_size": full_frame_size},
            ))
            break

        words = FRAME_HEADER_STRUCT.unpack_from(data, pos)
        raw_header = data[pos:pos + FRAME_HEADER_SIZE]
        page_offset = pos + FRAME_HEADER_SIZE

        if remaining < full_frame_size:
            frames.append(ParsedFrame(
                index=global_index,
                segment_index=current.segment_index,
                frame_number=frame_number + 1,
                header_offset=pos,
                page_offset=page_offset,
                page_number=words[FH_PAGE_NUMBER],
                db_size=words[FH_DB_SIZE],
                salt_1=words[FH_SALT_1],
                salt_2=words[FH_SALT_2],
                stored_checksum=(words[FH_CHECKSUM_1], words[FH_CHECKSUM_2]),
                computed_checksum=None,
                checksum_valid=None,
                salt_matches_header=(
                    (words[FH_SALT_1], words[FH_SALT_2]) == current.salt
                ),
                is_commit=words[FH_DB_SIZE] != 0,
                truncated=True,
                chain_alive=False,
                raw_header=raw_header,
            ))
            global_index += 1
            frame_number += 1
            anomalies.append(ParseAnomaly(
                kind="truncated_frame_page",
                offset=pos,
                message=(
                    f"frame {global_index} header is complete but only "
                    f"{remaining - FRAME_HEADER_SIZE} of {page_size} page "
                    "bytes remain; WAL chunk was cut mid-write"
                ),
                detail={
                    "frame_index": global_index - 1,
                    "page_number": words[FH_PAGE_NUMBER],
                    "expected_size": full_frame_size,
                },
            ))
            break

        page = data[page_offset:page_offset + page_size]
        chain_alive = checksum_seed is not None
        computed = frame_checksum(
            raw_header, page, checksum_seed or (0, 0), current.big_endian,
        )
        stored = (words[FH_CHECKSUM_1], words[FH_CHECKSUM_2])
        salt_ok = (words[FH_SALT_1], words[FH_SALT_2]) == current.salt

        frame = ParsedFrame(
            index=global_index,
            segment_index=current.segment_index,
            frame_number=frame_number + 1,
            header_offset=pos,
            page_offset=page_offset,
            page_number=words[FH_PAGE_NUMBER],
            db_size=words[FH_DB_SIZE],
            salt_1=words[FH_SALT_1],
            salt_2=words[FH_SALT_2],
            stored_checksum=stored,
            computed_checksum=computed,
            checksum_valid=stored == computed,
            salt_matches_header=salt_ok,
            is_commit=words[FH_DB_SIZE] != 0,
            truncated=False,
            chain_alive=chain_alive,
            raw_header=raw_header,
        )
        frames.append(frame)
        global_index += 1
        frame_number += 1
        # SQLite walks the checksum chain over every frame in sequence. A
        # frame carrying a stale salt is skipped (it does not advance the
        # chain); only an actual checksum mismatch on the current salt
        # breaks the chain and invalidates all later frames.
        if chain_alive and not salt_ok:
            # Stale frame: ignore it and preserve the running seed.
            pass
        elif chain_alive and frame.checksum_valid:
            checksum_seed = stored
        else:
            checksum_seed = None
        pos += full_frame_size

    return headers, frames, anomalies
