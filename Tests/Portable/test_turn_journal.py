import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portable"))
from turn_journal import (AgentTurnJournal, GitFileState, GitRecovery,
                          GitRepositoryInspector, JournalPersistence,
                          MAX_CAPTURE, ProjectVerifier, TurnJournalStore,
                          VerificationCommand)


@unittest.skipUnless(shutil.which("git"), "Git is required for repository tests")
class TurnJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Journal Tests")
        self.git("config", "core.autocrlf", "false")
        (self.root / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        (self.root / "renamed source.txt").write_text("rename me\n", encoding="utf-8")
        (self.root / "delete.txt").write_text("keep me\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.store = TurnJournalStore()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, capture_output=True, encoding="utf-8", check=True).stdout

    def begin(self):
        return self.store.begin(self.root, session_id="session:one", turn_id="turn", agent="codex", prompt="Implement a feature")

    def test_complete_turn_capture_preserves_rename_stage_and_untracked(self):
        journal = self.begin()
        self.assertEqual(journal.baseline.files, [])
        (self.root / "tracked.txt").write_text("modified\n", encoding="utf-8")
        self.git("mv", "renamed source.txt", "renamed destination.txt")
        (self.root / "delete.txt").unlink()
        (self.root / "new file.txt").write_text("created\n", encoding="utf-8")
        self.store.finish(journal.id)
        states = {item.path: item for item in journal.final_snapshot.files}
        self.assertEqual(states["renamed destination.txt"].original_path, "renamed source.txt")
        self.assertEqual(states["new file.txt"].status, "??")
        self.assertEqual(states["delete.txt"].content_fingerprint, "absent")
        self.assertEqual({item.attribution for item in journal.mutations}, {"inferred"})
        preview = self.store.preview_recovery(journal.id)
        self.assertTrue(preview["allowed"], preview)
        self.assertIn("renamed source.txt", preview["restorePaths"])
        self.assertEqual(preview["removePaths"], ["new file.txt"])
        result = self.store.recover(journal.id)
        self.assertTrue(result.success, result.message)
        self.assertEqual((self.root / "tracked.txt").read_text(), "baseline\n")
        self.assertTrue((self.root / "renamed source.txt").exists())
        self.assertFalse((self.root / "renamed destination.txt").exists())
        self.assertFalse((self.root / "new file.txt").exists())
        self.assertEqual(self.git("status", "--porcelain"), "")
        # Recovery never erases the evidence of what the agent changed.
        self.assertTrue(journal.mutations)

    def test_staged_new_file_and_unstaged_same_path_are_restored(self):
        journal = self.begin()
        (self.root / "new.txt").write_text("stage one")
        self.git("add", "new.txt")
        (self.root / "new.txt").write_text("stage two")
        self.store.finish(journal.id)
        self.assertTrue(self.store.recover(journal.id).success)
        self.assertFalse((self.root / "new.txt").exists())

    def test_recovery_refuses_later_same_status_content_changes(self):
        journal = self.begin()
        file = self.root / "tracked.txt"
        file.write_text("agent change\n")
        self.store.finish(journal.id)
        file.write_text("user change after turn\n")
        preview = self.store.preview_recovery(journal.id)
        self.assertFalse(preview["allowed"])
        self.assertFalse(self.store.recover(journal.id).success)
        self.assertEqual(file.read_text(), "user change after turn\n")

    def test_dirty_baseline_preserves_user_changes(self):
        (self.root / "tracked.txt").write_text("user started this\n")
        journal = self.begin()
        (self.root / "delete.txt").write_text("agent edits\n")
        self.store.finish(journal.id)
        self.assertTrue(journal.has_pre_existing_changes)
        self.assertFalse(journal.can_recover_safely)
        self.assertFalse(self.store.recover(journal.id).success)
        self.assertEqual((self.root / "tracked.txt").read_text(), "user started this\n")

    def test_head_change_blocks_recovery(self):
        journal = self.begin()
        (self.root / "tracked.txt").write_text("committed\n")
        self.git("commit", "-am", "agent commit", "-q")
        (self.root / "tracked.txt").write_text("then edited\n")
        self.store.finish(journal.id)
        self.assertFalse(self.store.preview_recovery(journal.id)["allowed"])
        self.assertFalse(self.store.recover(journal.id).success)

    def test_transcript_ingestion_never_invents_pre_task_baseline(self):
        events = [
            {"eventId": "p", "sessionId": "s", "turnId": "t", "eventType": "prompt", "path": str(self.root), "text": "Already executed", "timestamp": "2026-01-01T00:00:00Z"},
            {"eventId": "c", "sessionId": "s", "turnId": "t", "eventType": "tool_call", "toolCallId": "call1", "timestamp": "2026-01-01T00:00:01Z"},
            {"eventId": "r", "sessionId": "s", "turnId": "t", "eventType": "response", "timestamp": "2026-01-01T00:00:02Z"},
        ]
        (self.root / "tracked.txt").write_text("already changed")
        touched = self.store.ingest(events)
        self.assertEqual(len(touched), 1)
        journal = touched[0]
        self.assertEqual(journal.status, "completed")
        self.assertEqual(journal.tool_call_ids, ["call1"])
        self.assertIsNone(journal.baseline)
        self.assertFalse(journal.baseline_precedes_mutation)
        self.assertEqual(journal.mutations[0].attribution, "unknown")
        self.assertFalse(self.store.preview_recovery(journal.id)["allowed"])
        self.assertEqual(self.store.ingest(events), [])

    def test_large_unknown_file_blocks_recovery(self):
        journal = self.begin()
        (self.root / "large.bin").write_bytes(b"x" * (1024 * 1024 + 1))
        self.store.finish(journal.id)
        self.assertFalse(self.store.preview_recovery(journal.id)["allowed"])
        self.assertFalse(self.store.recover(journal.id).success)

    def test_recovery_path_validation_occurs_before_any_changes(self):
        journal = self.begin()
        (self.root / "tracked.txt").write_text("agent edit")
        self.store.finish(journal.id)
        result = GitRecovery.restore_clean_baseline(self.root, journal.baseline.head, ["../elsewhere"], journal.final_snapshot)
        self.assertFalse(result.success)
        self.assertEqual((self.root / "tracked.txt").read_text(), "agent edit")
        for value in ("../elsewhere", ".git/config", str(self.root)):
            with self.assertRaises(ValueError):
                GitRecovery._safe_path(self.root, value)

    def test_json_and_sqlite_roundtrip_and_store_reload(self):
        path = Path(self.temp.name) / "journals.json"
        database = Path(self.temp.name) / "evidence.sqlite3"
        store = TurnJournalStore(path, database)
        journal = store.begin(self.root, prompt="中文任务")
        (self.root / "tracked.txt").write_text("changed\n")
        store.finish(journal.id)
        command = VerificationCommand(sys.executable, ("-c", "print('independently verified')"), "test verifier")
        runs = store.verify(journal.id, [command])
        self.assertEqual(runs[0].exit_code, 0)
        self.assertEqual(TurnJournalStore(path, database).get(journal.id).to_dict(), journal.to_dict())
        self.assertEqual(TurnJournalStore(database=database).get(journal.id).to_dict(), journal.to_dict())
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schemaVersion"], 1)
        connection = sqlite3.connect(database)
        try:
            self.assertEqual(JournalPersistence.load_sqlite(connection, journal.id).to_dict(), journal.to_dict())
        finally:
            connection.close()

    def test_duplicate_begin_cannot_replace_baseline(self):
        journal = self.begin()
        (self.root / "tracked.txt").write_text("changed")
        with self.assertRaises(ValueError):
            self.begin()
        self.assertEqual(journal.baseline.files, [])


class VerificationTests(unittest.TestCase):
    def test_command_detection_matches_available_scripts_and_package_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"scripts":{"build":"build it", "lint":"lint it"}}')
            (root / "pnpm-lock.yaml").write_text("")
            commands = ProjectVerifier.commands(root)
            self.assertEqual([item.display_name for item in commands], ["pnpm run build"])

    def test_timeout_and_large_output_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            command = VerificationCommand(sys.executable, ("-c", "import time; print('started', flush=True); time.sleep(10)"), "slow check")
            start = time.monotonic()
            run = ProjectVerifier.run(command, directory, timeout=0.2)
            self.assertNotEqual(run.exit_code, 0)
            self.assertIn("timed out", run.standard_error)
            self.assertLess(time.monotonic() - start, 8)
            command = VerificationCommand(sys.executable, ("-c", "import sys; sys.stdout.write('x'*1000000); sys.stderr.write('y'*1000000)"), "verbose check")
            run = ProjectVerifier.run(command, directory, timeout=10)
            self.assertEqual(run.exit_code, 0)
            self.assertEqual(len(run.standard_output), MAX_CAPTURE)
            self.assertEqual(len(run.standard_error), MAX_CAPTURE)

    def test_missing_command_is_recorded_as_failed_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            run = ProjectVerifier.run(VerificationCommand("this-command-does-not-exist-agentreins", (), "missing"), directory)
        self.assertNotEqual(run.exit_code, 0)
        self.assertTrue(run.standard_error)

    def test_nul_porcelain_handles_spaces_and_rename_source(self):
        rows = GitRepositoryInspector.parse_porcelain(b" M space name\0R  renamed destination\0original source\0?? new file\0")
        self.assertEqual(rows[1].original_path, "original source")
        self.assertEqual([item.path for item in rows], ["new file", "renamed destination", "space name"])


if __name__ == "__main__":
    unittest.main()
