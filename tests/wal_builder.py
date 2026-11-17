"""Synthetic WAL file builder used by the test-suite.

It produces byte-identical, checksum-correct WAL frames so that tests can
corrupt, truncate or reset individual parts deliberately.
"""

from __future__ import annotations

from wal_auditor.format import (
    FRAME_HEADER_SIZE,
    FRAME_HEADER_STRUCT,
    WAL_HEADER_SIZE,
    WAL_HEADER_STRUCT,
    WAL_MAGIC_BE,
    WAL_MAGIC_LE,
    frame_checksum,
    header_checksum,
)


def make_page(page_number: int, page_size: int = 4096,
              marker: int = 0) -> bytes:
    """A deterministic fake page whose content encodes its identity."""
    page = bytearray(page_size)
    page[0:4] = page_number.to_bytes(4, "big")
    page[4:8] = marker.to_bytes(4, "big")
    return bytes(page)


class WalBuilder:
    def __init__(self, page_size: int = 4096,
                 salt: tuple[int, int] = (0x11111111, 0x22222222),
                 checkpoint_seq: int = 0,
                 big_endian: bool = True):
        self.page_size = page_size
        self.big_endian = big_endian
        self.salt = salt
        self.checkpoint_seq = checkpoint_seq
        self.buffer = bytearray()
        self._append_header()
        self.seed = self._header_checksum()
        self.frame_count = 0

    def _magic(self) -> int:
        # Mirror real SQLite builds: ordinary WAL integers are always
        # big-endian; the magic only hints at the checksum word order.
        return WAL_MAGIC_BE

    def _header_words(self) -> tuple[int, ...]:
        checksum = self._header_checksum()
        return (
            self._magic(),
            3007000,
            self.page_size,
            self.checkpoint_seq,
            self.salt[0],
            self.salt[1],
            checksum[0],
            checksum[1],
        )

    def _header_checksum(self) -> tuple[int, int]:
        partial = WAL_HEADER_STRUCT.pack(
            self._magic(), 3007000, self.page_size, self.checkpoint_seq,
            self.salt[0], self.salt[1], 0, 0,
        )
        return header_checksum(partial, self.big_endian)

    def _append_header(self) -> int:
        offset = len(self.buffer)
        self.buffer.extend(WAL_HEADER_STRUCT.pack(*self._header_words()))
        return offset

    def add_frame(self, page_number: int, db_size: int = 0,
                  page: bytes | None = None,
                  salt: tuple[int, int] | None = None,
                  bad_checksum: bool = False) -> int:
        if page is None:
            page = make_page(page_number, self.page_size, self.frame_count)
        if len(page) != self.page_size:
            raise ValueError("page length must match the WAL page size")

        frame_salt = salt if salt is not None else self.salt
        # Stale-salt frames still carry a checksum computed over the same
        # running chain in a real WAL file; only the salt differs.
        seed = (0, 0) if bad_checksum else self.seed
        partial = FRAME_HEADER_STRUCT.pack(
            page_number, db_size, frame_salt[0], frame_salt[1], 0, 0,
        )
        checksum = frame_checksum(partial, page, seed, self.big_endian)
        if bad_checksum:
            checksum = (checksum[0] ^ 0xFFFFFFFF, checksum[1])
        header = FRAME_HEADER_STRUCT.pack(
            page_number, db_size, frame_salt[0], frame_salt[1],
            checksum[0], checksum[1],
        )
        frame_index = self.frame_count
        self.buffer.extend(header)
        self.buffer.extend(page)
        self.frame_count += 1
        if salt is None and not bad_checksum:
            self.seed = checksum
        return frame_index

    def add_commit(self, page_number: int, db_size: int,
                   page: bytes | None = None) -> int:
        return self.add_frame(page_number, db_size=db_size, page=page)

    def corrupt_frame_page(self, frame_index: int) -> int:
        """Flip a byte inside the page body of a finished frame."""
        offset = (
            WAL_HEADER_SIZE
            + frame_index * (FRAME_HEADER_SIZE + self.page_size)
            + FRAME_HEADER_SIZE
            + 7
        )
        self.buffer[offset] ^= 0x01
        return offset

    def truncate(self, byte_count: int) -> None:
        del self.buffer[byte_count:]

    def append_new_header(self, page_size: int | None = None,
                          salt: tuple[int, int] | None = None,
                          checkpoint_seq: int | None = None) -> int:
        """Start a new WAL segment inside the same file (WAL reuse)."""
        if page_size is not None:
            self.page_size = page_size
        if salt is not None:
            self.salt = salt
        if checkpoint_seq is not None:
            self.checkpoint_seq = checkpoint_seq
        offset = self._append_header()
        self.seed = self._header_checksum()
        return offset

    def frame_header_offset(self, frame_index: int) -> int:
        return (
            WAL_HEADER_SIZE
            + frame_index * (FRAME_HEADER_SIZE + self.page_size)
        )

    def build(self) -> bytes:
        return bytes(self.buffer)
