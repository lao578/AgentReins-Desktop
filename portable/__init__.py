"""Portable AgentReins runtime.

The imports below intentionally expose the parity backend without importing
the Tk desktop module (and therefore remain safe in headless service builds).
"""

from .turn_journal import (AgentTurnJournal, FileMutation, GitRecovery,
                           GitRepositoryInspector, GitSnapshot,
                           JournalPersistence, ProjectVerifier,
                           RecoveryResult, TurnJournalStore, VerificationCommand,
                           VerificationRun)

__all__ = [
    "AgentTurnJournal", "FileMutation", "GitRecovery",
    "GitRepositoryInspector", "GitSnapshot", "JournalPersistence",
    "ProjectVerifier", "RecoveryResult", "TurnJournalStore",
    "VerificationCommand", "VerificationRun",
]
