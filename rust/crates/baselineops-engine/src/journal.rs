use baselineops_domain::{PlanId, ResultId, Sha256Digest, canonical_json_bytes};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const JOURNAL_MAGIC: &[u8] = b"BASELINEOPS-JOURNAL-V1\n";
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Mutation-boundary event retained in the protected worker run directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEvent {
    /// Operator approved the exact plan digest.
    PlanApproved {
        /// Plan identity.
        plan_id: PlanId,
        /// Canonical approved plan digest.
        plan_digest: Sha256Digest,
    },
    /// An action is about to mutate state after precondition revalidation.
    ActionStarted {
        /// Stable action identifier.
        action_id: String,
        /// Digest of pre-state captured before mutation.
        pre_state_digest: Sha256Digest,
    },
    /// An action reached a terminal boundary.
    ActionFinished {
        /// Stable action identifier.
        action_id: String,
        /// Capability-defined terminal status.
        status: String,
        /// Digest of post-state or action receipt.
        receipt_digest: Sha256Digest,
    },
    /// Worker finalized the result and artifact manifest.
    RunFinished {
        /// Result identity.
        result_id: ResultId,
        /// Digest of the final result envelope.
        result_digest: Sha256Digest,
    },
}

/// One hash-chained journal record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct JournalRecord {
    /// Monotonic record sequence.
    pub sequence: u64,
    /// Worker-trusted timestamp.
    pub timestamp: DateTime<Utc>,
    /// Previous record hash, or all zeros for the first record.
    pub previous_hash: Sha256Digest,
    /// Event payload.
    pub payload: JournalEvent,
    /// Hash of sequence, timestamp, previous hash, and payload.
    pub record_hash: Sha256Digest,
}

/// Append-only writer for a tamper-evident journal.
pub struct Journal {
    path: PathBuf,
    file: File,
    next_sequence: u64,
    previous_hash: Sha256Digest,
}

/// Verified journal contents and the chain anchor needed to detect truncation.
#[derive(Clone, Debug)]
pub struct JournalSnapshot {
    /// Records in their file order after hash-chain verification.
    pub records: Vec<JournalRecord>,
    /// Digest of the final retained record, or the empty-chain digest.
    pub terminal_hash: Sha256Digest,
}

/// Recovery result for a journal that ended in an interrupted frame write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalRecovery {
    /// Number of incomplete trailing bytes removed. Complete invalid records are never removed.
    pub truncated_bytes: u64,
}

impl Journal {
    /// Create a new journal without replacing an existing run file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the new journal cannot be created, written, or synced.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(JOURNAL_MAGIC)?;
        file.sync_all()?;
        Ok(Self {
            path,
            file,
            next_sequence: 0,
            previous_hash: Sha256Digest::of_bytes([]),
        })
    }

    /// Open an existing journal after validating every complete record.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or altered journal, including an incomplete
    /// trailing frame. Use [`Self::recover`] only after a crash boundary is known.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let snapshot = Self::read(&path)?;
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok(Self {
            path,
            file,
            next_sequence: u64::try_from(snapshot.records.len())
                .map_err(|_| JournalError::SequenceOverflow)?,
            previous_hash: snapshot.terminal_hash,
        })
    }

    /// Read and verify a complete journal without granting append authority.
    ///
    /// # Errors
    ///
    /// Detects framing edits, reordered records, hash edits, and incomplete trailing frames.
    pub fn read(path: impl AsRef<Path>) -> Result<JournalSnapshot, JournalError> {
        let bytes = read_all(path)?;
        let parsed = parse_journal(&bytes)?;
        if parsed.trailing_bytes != 0 {
            return Err(JournalError::IncompleteFrame);
        }
        Ok(parsed.snapshot)
    }

    /// Verify a journal against an independently retained terminal hash.
    ///
    /// A hash chain detects edits and reordering by itself. Supplying the retained
    /// terminal hash additionally detects a valid-prefix truncation.
    ///
    /// # Errors
    ///
    /// Returns an error when framing or chain integrity fails, or when the retained
    /// terminal anchor proves the journal has been truncated.
    pub fn verify(
        path: impl AsRef<Path>,
        expected_terminal_hash: Sha256Digest,
    ) -> Result<JournalSnapshot, JournalError> {
        let snapshot = Self::read(path)?;
        if snapshot.terminal_hash != expected_terminal_hash {
            return Err(JournalError::TerminalHashMismatch);
        }
        Ok(snapshot)
    }

    /// Truncate only an incomplete trailing frame, then reopen a verified append writer.
    ///
    /// # Errors
    ///
    /// Never repairs a complete malformed, reordered, or hash-edited record. Those
    /// conditions are evidence tampering rather than recoverable interruption.
    pub fn recover(path: impl AsRef<Path>) -> Result<(Self, JournalRecovery), JournalError> {
        let path = path.as_ref().to_path_buf();
        let bytes = read_all(&path)?;
        let parsed = parse_journal(&bytes)?;
        let recovery = JournalRecovery {
            truncated_bytes: u64::try_from(parsed.trailing_bytes)
                .map_err(|_| JournalError::SequenceOverflow)?,
        };
        if parsed.trailing_bytes != 0 {
            let length = u64::try_from(bytes.len() - parsed.trailing_bytes)
                .map_err(|_| JournalError::SequenceOverflow)?;
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(length)?;
            file.sync_all()?;
        }
        let journal = Self::open(path)?;
        Ok((journal, recovery))
    }

    /// Append, flush, and sync one mutation-boundary record.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical serialization, record sizing, writing, or
    /// durable synchronization fails.
    pub fn append(
        &mut self,
        timestamp: DateTime<Utc>,
        payload: JournalEvent,
    ) -> Result<JournalRecord, JournalError> {
        let hash_payload = (&self.next_sequence, timestamp, self.previous_hash, &payload);
        let record_hash = Sha256Digest::of_bytes(canonical_json_bytes(&hash_payload)?);
        let record = JournalRecord {
            sequence: self.next_sequence,
            timestamp,
            previous_hash: self.previous_hash,
            payload,
            record_hash,
        };
        let bytes = canonical_json_bytes(&record)?;
        let length = u32::try_from(bytes.len()).map_err(|_| JournalError::RecordTooLarge)?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.previous_hash = record_hash;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(record)
    }

    /// Terminal chain hash. It is meaningful only when retained independently.
    pub const fn terminal_hash(&self) -> Sha256Digest {
        self.previous_hash
    }

    /// Journal path beneath the worker-controlled protected run directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

struct ParsedJournal {
    snapshot: JournalSnapshot,
    trailing_bytes: usize,
}

fn read_all(path: impl AsRef<Path>) -> Result<Vec<u8>, JournalError> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(path)?
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn parse_journal(bytes: &[u8]) -> Result<ParsedJournal, JournalError> {
    if !bytes.starts_with(JOURNAL_MAGIC) {
        return Err(JournalError::BadMagic);
    }
    let mut offset = JOURNAL_MAGIC.len();
    let mut records = Vec::new();
    let mut previous_hash = Sha256Digest::of_bytes([]);
    let mut sequence = 0_u64;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < 4 {
            return Ok(ParsedJournal {
                snapshot: JournalSnapshot {
                    records,
                    terminal_hash: previous_hash,
                },
                trailing_bytes: remaining,
            });
        }
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("length"));
        let length = usize::try_from(length).map_err(|_| JournalError::RecordTooLarge)?;
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(JournalError::RecordTooLarge);
        }
        let frame_end = offset
            .checked_add(4 + length)
            .ok_or(JournalError::RecordTooLarge)?;
        if frame_end > bytes.len() {
            return Ok(ParsedJournal {
                snapshot: JournalSnapshot {
                    records,
                    terminal_hash: previous_hash,
                },
                trailing_bytes: remaining,
            });
        }
        let record = serde_json::from_slice::<JournalRecord>(&bytes[offset + 4..frame_end])
            .map_err(JournalError::InvalidRecord)?;
        if record.sequence != sequence {
            return Err(JournalError::SequenceMismatch);
        }
        if record.previous_hash != previous_hash {
            return Err(JournalError::PreviousHashMismatch);
        }
        let hash_payload = (
            record.sequence,
            record.timestamp,
            record.previous_hash,
            &record.payload,
        );
        if Sha256Digest::of_bytes(canonical_json_bytes(&hash_payload)?) != record.record_hash {
            return Err(JournalError::RecordHashMismatch);
        }
        previous_hash = record.record_hash;
        records.push(record);
        sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        offset = frame_end;
    }
    Ok(ParsedJournal {
        snapshot: JournalSnapshot {
            records,
            terminal_hash: previous_hash,
        },
        trailing_bytes: 0,
    })
}

/// Journal append failures.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// File operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Canonical serialization failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// A record exceeded the 32-bit framing limit.
    #[error("journal record exceeded the framing limit")]
    RecordTooLarge,
    /// The file did not begin with the exact journal marker.
    #[error("journal magic is invalid")]
    BadMagic,
    /// The final frame is incomplete and must be recovered explicitly.
    #[error("journal ends with an incomplete frame")]
    IncompleteFrame,
    /// A complete frame could not be parsed as a strict journal record.
    #[error("journal record is invalid: {0}")]
    InvalidRecord(serde_json::Error),
    /// A record's sequence was not monotonic.
    #[error("journal record sequence is invalid")]
    SequenceMismatch,
    /// The sequence could not be advanced.
    #[error("journal record sequence overflowed")]
    SequenceOverflow,
    /// A record was not bound to the prior chain hash.
    #[error("journal previous hash does not match")]
    PreviousHashMismatch,
    /// A record's canonical payload hash changed.
    #[error("journal record hash does not match")]
    RecordHashMismatch,
    /// The chain is a valid prefix but not the independently retained terminal chain.
    #[error("journal terminal hash does not match")]
    TerminalHashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_hash_chain_advances_and_file_is_nonempty() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("apply.journal");
        let mut journal = Journal::create(&path).expect("journal");
        let initial = journal.terminal_hash();
        let record = journal
            .append(
                Utc::now(),
                JournalEvent::PlanApproved {
                    plan_id: PlanId::new(),
                    plan_digest: Sha256Digest::of_bytes(b"plan"),
                },
            )
            .expect("append");
        assert_eq!(record.previous_hash, initial);
        assert_eq!(journal.terminal_hash(), record.record_hash);
        assert!(std::fs::metadata(path).expect("metadata").len() > JOURNAL_MAGIC.len() as u64);
    }

    #[test]
    fn verification_detects_edit_reorder_and_prefix_truncation() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("apply.journal");
        let mut journal = Journal::create(&path).expect("journal");
        for label in ["first", "second"] {
            journal
                .append(
                    Utc::now(),
                    JournalEvent::ActionStarted {
                        action_id: label.into(),
                        pre_state_digest: Sha256Digest::of_bytes(label),
                    },
                )
                .expect("append");
        }
        let terminal = journal.terminal_hash();
        Journal::verify(&path, terminal).expect("valid journal");
        let original = std::fs::read(&path).expect("bytes");
        let first_length = u32::from_le_bytes(
            original[JOURNAL_MAGIC.len()..JOURNAL_MAGIC.len() + 4]
                .try_into()
                .expect("first length"),
        );
        let first_end = JOURNAL_MAGIC.len() + 4 + usize::try_from(first_length).expect("length");
        let mut reordered = JOURNAL_MAGIC.to_vec();
        reordered.extend_from_slice(&original[first_end..]);
        reordered.extend_from_slice(&original[JOURNAL_MAGIC.len()..first_end]);
        let reordered_path = root.path().join("reordered.journal");
        std::fs::write(&reordered_path, reordered).expect("reorder");
        assert!(matches!(
            Journal::read(reordered_path),
            Err(JournalError::SequenceMismatch)
        ));
        let mut bytes = std::fs::read(&path).expect("bytes");
        *bytes.last_mut().expect("last") ^= 1;
        std::fs::write(&path, bytes).expect("edit");
        assert!(matches!(
            Journal::read(&path),
            Err(JournalError::InvalidRecord(_) | JournalError::RecordHashMismatch)
        ));

        let path = root.path().join("truncated.journal");
        let mut journal = Journal::create(&path).expect("journal");
        journal
            .append(
                Utc::now(),
                JournalEvent::PlanApproved {
                    plan_id: PlanId::new(),
                    plan_digest: Sha256Digest::of_bytes(b"plan"),
                },
            )
            .expect("append");
        let expected = journal.terminal_hash();
        let bytes = std::fs::read(&path).expect("bytes");
        std::fs::write(&path, &bytes[..JOURNAL_MAGIC.len()]).expect("truncate");
        assert!(matches!(
            Journal::verify(&path, expected),
            Err(JournalError::TerminalHashMismatch)
        ));
    }

    #[test]
    fn recovery_only_removes_an_incomplete_last_frame() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("recover.journal");
        let mut journal = Journal::create(&path).expect("journal");
        journal
            .append(
                Utc::now(),
                JournalEvent::PlanApproved {
                    plan_id: PlanId::new(),
                    plan_digest: Sha256Digest::of_bytes(b"plan"),
                },
            )
            .expect("append");
        let length_before = std::fs::metadata(&path).expect("metadata").len();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append file");
        file.write_all(&[5, 0, 0, 0, 1, 2]).expect("partial frame");
        file.sync_all().expect("sync");
        assert!(matches!(
            Journal::read(&path),
            Err(JournalError::IncompleteFrame)
        ));
        let (_, recovery) = Journal::recover(&path).expect("recovered");
        assert_eq!(recovery.truncated_bytes, 6);
        assert_eq!(
            std::fs::metadata(path).expect("metadata").len(),
            length_before
        );
    }
}
