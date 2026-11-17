from __future__ import annotations

import io
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wal_auditor.__main__ import main
from wal_auditor.auditor import audit_wal
from wal_auditor.format import (
    FRAME_HEADER_SIZE,
    WAL_HEADER_SIZE,
    WAL_MAGIC_BE,
    is_valid_page_size,
    wal_checksum,
)
from wal_auditor.report import format_json, format_text

from tests.wal_builder import WalBuilder, make_page


class ChecksumTests(unittest.TestCase):
    def test_checksum_alternating_accumulators(self):
        s0, s1 = wal_checksum((5).to_bytes(4, "big"))
        self.assertEqual((s0, s1), (5, 0))
        s0, s1 = wal_checksum((5).to_bytes(4, "big") + (7).to_bytes(4, "big"))
        self.assertEqual(s0, 5)
        self.assertEqual(s1, (0 + 5 + 7))

    def test_page_size_validation(self):
        self.assertTrue(is_valid_page_size(4096))
        self.assertTrue(is_valid_page_size(65536))
        for bad in (0, 100, 3000, 70000):
            self.assertFalse(is_valid_page_size(bad))


class AuditTests(unittest.TestCase):
    def _audit(self, builder: WalBuilder):
        data = builder.build()
        with tempfile.TemporaryDirectory() as tmp:
            wal_path = Path(tmp) / "test.db-wal"
            wal_path.write_bytes(data)
            return audit_wal(wal_path)

    def test_little_endian_checksum_variant(self):
        builder = WalBuilder(big_endian=False)
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        report = self._audit(builder)
        self.assertEqual(report.segments[0]["big_endian"], False)
        self.assertEqual(report.valid_frame_count, 2)
        self.assertEqual(len(report.visible_versions), 1)

    def test_magic_bytes_inside_page_do_not_false_start_segment(self):
        builder = WalBuilder()
        tricky_page = bytearray(builder.page_size)
        tricky_page[0:4] = WAL_MAGIC_BE.to_bytes(4, "big")
        builder.add_commit(1, db_size=1, page=bytes(tricky_page))
        builder.add_commit(2, db_size=2)
        report = self._audit(builder)
        self.assertEqual(len(report.segments), 1)
        self.assertEqual(report.frame_count, 2)
        self.assertEqual(len(report.visible_versions), 2)

    def test_multiple_commits_rebuild_versions(self):
        builder = WalBuilder()
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        builder.add_frame(3)
        builder.add_commit(1, db_size=3)

        report = self._audit(builder)
        self.assertEqual(report.frame_count, 4)
        self.assertEqual(report.valid_frame_count, 4)
        self.assertEqual(len(report.visible_versions), 2)
        self.assertEqual(report.last_commit_frame, 3)
        self.assertEqual(report.visible_versions[0].pages_visible, 2)
        self.assertEqual(report.visible_versions[1].pages_visible, 3)
        self.assertEqual(report.uncommitted_tail, [])
        self.assertEqual(report.orphan_frames, [])
        self.assertEqual(report.checksum_failures, [])

    def test_uncommitted_tail_is_not_a_version(self):
        builder = WalBuilder()
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        builder.add_frame(3)
        builder.add_frame(4)

        report = self._audit(builder)
        self.assertEqual(len(report.visible_versions), 1)
        self.assertEqual(report.last_commit_frame, 1)
        self.assertEqual(report.uncommitted_tail, [2, 3])
        # The tail frames are structurally valid but never committed; they
        # must be called out explicitly instead of treated as history.
        tail_lines = [
            line for line in format_text(report).splitlines()
            if "未提交尾部帧" in line
        ]
        self.assertEqual(len(tail_lines), 1)
        self.assertIn("2", tail_lines[0])
        self.assertIn("3", tail_lines[0])
        history = {
            history.page_number: history
            for history in report.page_histories
        }
        self.assertTrue(history[1].visible_in_last_commit)
        self.assertFalse(history[3].visible_in_last_commit)
        self.assertFalse(history[4].visible_in_last_commit)

    def test_corrupt_checksum_breaks_chain_and_orphans_later_frames(self):
        builder = WalBuilder()
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        builder.add_frame(3)
        builder.corrupt_frame_page(2)
        builder.add_commit(1, db_size=3)

        report = self._audit(builder)
        mismatch = [
            failure for failure in report.checksum_failures
            if failure["chain_alive"]
        ]
        self.assertEqual(len(mismatch), 1)
        failure = mismatch[0]
        self.assertEqual(failure["frame_index"], 2)

        # Frames at index 2 and 3 cannot be validated anymore.
        orphan_indices = {orphan.frame_index for orphan in report.orphan_frames}
        self.assertEqual(orphan_indices, {2, 3})
        reasons = {
            orphan.frame_index: orphan.reasons
            for orphan in report.orphan_frames
        }
        self.assertIn("checksum_mismatch", reasons[2])
        self.assertIn("checksum_chain_broken", reasons[3])
        self.assertEqual(len(report.visible_versions), 1)
        self.assertEqual(report.last_commit_frame, 1)

    def test_page_reuse_records_overwrite_timeline(self):
        builder = WalBuilder()
        builder.add_frame(5, page=make_page(5, marker=1))
        builder.add_commit(5, db_size=5, page=make_page(5, marker=2))
        builder.add_commit(5, db_size=5, page=make_page(5, marker=3))

        report = self._audit(builder)
        history = next(h for h in report.page_histories if h.page_number == 5)
        self.assertEqual(history.write_count, 3)
        self.assertEqual(len(history.overwrites), 2)
        self.assertEqual(history.overwrites[0].frame_index, 1)
        self.assertEqual(history.overwrites[0].overwrote_frame_index, 0)
        self.assertEqual(history.overwrites[1].frame_index, 2)
        self.assertTrue(history.visible_in_last_commit)

    def test_chunk_truncation_inside_frame(self):
        builder = WalBuilder()
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        builder.add_frame(3)
        cut = (
            WAL_HEADER_SIZE
            + 2 * (FRAME_HEADER_SIZE + builder.page_size)
            + 10
        )
        builder.truncate(cut)

        report = self._audit(builder)
        self.assertTrue(report.truncated)
        kinds = {anomaly.kind for anomaly in report.anomalies}
        self.assertIn("truncated_frame_header", kinds)
        self.assertEqual(len(report.visible_versions), 1)

    def test_chunk_truncation_inside_page_body(self):
        builder = WalBuilder()
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        builder.add_frame(3)
        cut = (
            WAL_HEADER_SIZE
            + 2 * (FRAME_HEADER_SIZE + builder.page_size)
            + FRAME_HEADER_SIZE
            + 100
        )
        builder.truncate(cut)

        report = self._audit(builder)
        self.assertTrue(report.truncated)
        kinds = {anomaly.kind for anomaly in report.anomalies}
        self.assertIn("truncated_frame_page", kinds)
        orphan = report.orphan_frames[-1]
        self.assertEqual(orphan.frame_index, 2)
        self.assertIn("truncated_frame", orphan.reasons)

    def test_wal_index_missing_does_not_block_audit(self):
        builder = WalBuilder()
        builder.add_commit(1, db_size=1)
        report = self._audit(builder)
        self.assertFalse(report.wal_index_present)
        self.assertEqual(len(report.visible_versions), 1)

    def test_stale_salt_frame_is_orphan_and_not_visible(self):
        builder = WalBuilder()
        builder.add_frame(1)
        builder.add_commit(2, db_size=2)
        # Frame written with an old salt: leftover from a previous WAL run.
        builder.add_frame(9, salt=(0x99999999, 0xAAAAAAAA))
        builder.add_commit(3, db_size=3)

        report = self._audit(builder)
        salt_failure = report.salt_failures[0]
        self.assertEqual(salt_failure["frame_index"], 2)
        orphan = next(o for o in report.orphan_frames if o.frame_index == 2)
        self.assertIn("stale_salt", orphan.reasons)
        # Later valid frames keep working because salt mismatch alone does
        # not invalidate the checksum chain of the current incarnation.
        self.assertEqual(len(report.visible_versions), 2)
        self.assertEqual(report.last_commit_frame, 3)

    def test_page_size_change_across_segments(self):
        builder = WalBuilder(page_size=4096)
        builder.add_commit(1, db_size=1)
        builder.append_new_header(
            page_size=8192,
            salt=(0x33333333, 0x44444444),
            checkpoint_seq=1,
        )
        builder.add_commit(2, db_size=2)

        report = self._audit(builder)
        self.assertEqual(len(report.segments), 2)
        self.assertEqual(report.segments[0]["page_size"], 4096)
        self.assertEqual(report.segments[1]["page_size"], 8192)
        change = report.page_size_changes[0]
        self.assertEqual(
            (change["previous_page_size"], change["current_page_size"]),
            (4096, 8192),
        )
        self.assertEqual(len(report.visible_versions), 2)

    def test_concurrent_checkpoint_trace_and_duplicate_salt(self):
        builder = WalBuilder(salt=(0x11111111, 0x22222222))
        builder.add_commit(1, db_size=1)
        builder.append_new_header(
            salt=(0x55555555, 0x66666666), checkpoint_seq=1
        )
        builder.add_commit(2, db_size=2)
        # WAL reused again, but the salt pair repeats the first one.
        builder.append_new_header(
            salt=(0x11111111, 0x22222222), checkpoint_seq=2
        )
        builder.add_commit(3, db_size=3)

        report = self._audit(builder)
        kinds = {trace.kind for trace in report.checkpoint_traces}
        self.assertIn("checkpoint_sequence_advance", kinds)
        self.assertIn("duplicate_salt", kinds)
        self.assertEqual(len(report.visible_versions), 3)

    def test_invalid_header_checksum_stops_scan(self):
        builder = WalBuilder()
        data = bytearray(builder.build())
        data[28] ^= 0xFF
        with tempfile.TemporaryDirectory() as tmp:
            wal_path = Path(tmp) / "bad.db-wal"
            wal_path.write_bytes(bytes(data))
            report = audit_wal(wal_path)
        self.assertEqual(report.segments, [])
        self.assertEqual(
            report.anomalies[0].kind, "invalid_wal_header"
        )

    def test_empty_wal_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal_path = Path(tmp) / "empty.db-wal"
            wal_path.write_bytes(b"")
            report = audit_wal(wal_path)
        self.assertEqual(report.frame_count, 0)
        self.assertIsNone(report.last_commit_frame)
        self.assertEqual(report.visible_versions, [])

    def test_json_report_is_serializable_and_complete(self):
        builder = WalBuilder()
        builder.add_commit(1, db_size=1)
        report = self._audit(builder)
        payload = json.loads(format_json(report))
        self.assertEqual(payload["last_commit_frame"], 0)
        self.assertIn("page_histories", payload)
        self.assertIn("orphan_frames", payload)
        self.assertIn("checkpoint_traces", payload)

    def test_cli_text_and_json_output(self):
        builder = WalBuilder()
        builder.add_commit(1, db_size=1)
        data = builder.build()
        with tempfile.TemporaryDirectory() as tmp:
            wal_path = Path(tmp) / "cli.db-wal"
            wal_path.write_bytes(data)
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main([str(wal_path)])
            self.assertEqual(exit_code, 0)
            self.assertIn("SQLite WAL 取证审计报告", buffer.getvalue())

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main([str(wal_path), "--json"])
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["frame_count"], 1)


@unittest.skipUnless(
    hasattr(sqlite3, "connect"), "sqlite3 unavailable"
)
class RealSqliteWalTests(unittest.TestCase):
    def test_audit_real_sqlite_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "real.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE evidence(id INTEGER PRIMARY KEY, note TEXT)"
                )
                # Bulk writes force SQLite to flush real frames into the WAL.
                connection.executemany(
                    "INSERT INTO evidence(note) VALUES(?)",
                    [(f"committed row {index}",) for index in range(400)],
                )
                connection.commit()
                connection.executemany(
                    "INSERT INTO evidence(note) VALUES(?)",
                    [(f"second batch {index}",) for index in range(400)],
                )
                connection.commit()
                connection.executemany(
                    "INSERT INTO evidence(note) VALUES(?)",
                    [(f"uncommitted {index}",) for index in range(400)],
                )
                # Keep the transaction open so the WAL is not checkpointed.
                wal_path = Path(str(db_path) + "-wal")
                self.assertTrue(wal_path.exists())
                report = audit_wal(wal_path)
                self.assertGreaterEqual(report.frame_count, 1)
                self.assertGreaterEqual(len(report.visible_versions), 1)
                self.assertIsNotNone(report.last_commit_frame)
                # Every validated frame must carry the current header salt.
                for failure in report.salt_failures:
                    self.assertNotEqual(
                        failure["frame_salt"], failure["header_salt"]
                    )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
