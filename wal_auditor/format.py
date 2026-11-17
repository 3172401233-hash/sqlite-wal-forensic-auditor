"""SQLite WAL binary format constants and checksum primitives.

Reference: SQLite WAL file format (https://www.sqlite.org/walformat.html).

All multi-byte integers in a WAL file are big-endian. The two checksum
fields inside the WAL header and every frame header are interpreted as a
sequence of big-endian 32-bit words as well; the only little-endian
variation of the format swaps the interpretation of those checksum words.
"""

from __future__ import annotations

import struct

WAL_MAGIC_BE = 0x377F0682
WAL_MAGIC_LE = 0x377F0683
WAL_MAGICS = (WAL_MAGIC_BE, WAL_MAGIC_LE)

WAL_HEADER_SIZE = 32
FRAME_HEADER_SIZE = 24

# WAL header layout (big-endian uint32 words).
WAL_HEADER_STRUCT = struct.Struct(">IIIIIIII")
# Frame header layout: page number, db size after commit, salt-1, salt-2,
# checksum-1, checksum-2.
FRAME_HEADER_STRUCT = struct.Struct(">IIIIII")

# Offsets (word index) inside a frame header.
FH_PAGE_NUMBER = 0
FH_DB_SIZE = 1
FH_SALT_1 = 2
FH_SALT_2 = 3
FH_CHECKSUM_1 = 4
FH_CHECKSUM_2 = 5

# WAL header word indices.
WH_MAGIC = 0
WH_FILE_FORMAT = 1
WH_PAGE_SIZE = 2
WH_CHECKPOINT_SEQ = 3
WH_SALT_1 = 4
WH_SALT_2 = 5
WH_CHECKSUM_1 = 6
WH_CHECKSUM_2 = 7

MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 65536

# Frame header db-size field is zero for non-commit frames.
NON_COMMIT_DB_SIZE = 0


def wal_checksum(data: bytes, seed: tuple[int, int] = (0, 0),
                 big_endian: bool = True) -> tuple[int, int]:
    """Compute the WAL checksum over ``data``.

    The checksum is a running pair of 32-bit accumulators. Every 32-bit
    word of ``data`` (which must have a length that is a multiple of four)
    is folded into one of the two accumulators in alternation.
    """
    if len(data) % 4:
        raise ValueError("checksum input length must be a multiple of 4")

    s0, s1 = seed
    # The checksum word order is a property of the WAL incarnation, not of
    # the big-endian integer layout used by ordinary WAL fields.
    prefix = ">" if big_endian else "<"
    count = len(data) // 4
    for index in range(count):
        word = struct.unpack_from(prefix + "I", data, index * 4)[0]
        if index % 2 == 0:
            s0 = (s0 + s1 + word) & 0xFFFFFFFF
        else:
            s1 = (s1 + s0 + word) & 0xFFFFFFFF
    return s0, s1


def header_checksum(header: bytes, big_endian: bool) -> tuple[int, int]:
    """Checksum stored in a WAL header covers its first 24 bytes."""
    return wal_checksum(header[:24], (0, 0), big_endian)


def frame_checksum(frame_header: bytes, page: bytes,
                   seed: tuple[int, int],
                   big_endian: bool) -> tuple[int, int]:
    """Checksum of a frame covers its first 8 header bytes plus the page."""
    return wal_checksum(frame_header[:8] + page, seed, big_endian)


def is_valid_page_size(page_size: int) -> bool:
    return (
        MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE
        and page_size & (page_size - 1) == 0
    )
