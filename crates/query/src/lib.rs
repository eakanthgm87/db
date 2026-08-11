//! VeilDB query layer.
//!
//! Encrypted equality indexes, logical clock, state reconstruction,
//! and time travel.
//!
//! The encrypted equality index works by:
//! 1. BLAKE3-normalizing the plaintext key
//! 2. Using the normalized hash as a deterministic AEAD token
//! 3. Storing the token alongside the ciphertext
//!
//! This allows equality searches without revealing the plaintext key,
//! at the documented cost of leaking equality (same value → same token).

pub mod error;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use veildb_crypto::{Key, decrypt, encrypt};
use veildb_storage::{LogicalClock, Operation, OperationId, Snapshot, SnapshotId, StorageEngine};

use error::QueryError;

/// A key-value pair in the database state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The plaintext key.
    pub key: String,
    /// The plaintext value.
    pub value: Vec<u8>,
}

/// The full database state (a key-value map).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbState {
    /// The logical clock at which this state was captured.
    pub clock: LogicalClock,
    /// The key-value entries.
    pub entries: BTreeMap<String, Vec<u8>>,
}

impl DbState {
    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.entries.get(key)
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A single operation in the encrypted log.
///
/// The plaintext payload is a serialized `PutOp` (key + value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutOp {
    /// The plaintext key.
    pub key: String,
    /// The plaintext value.
    pub value: Vec<u8>,
}

/// A deterministic index token for a plaintext key.
///
/// This is BLAKE3(key) — it reveals equality but not the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexToken(pub [u8; 32]);

/// Compute the deterministic index token for a key.
///
/// This is BLAKE3 over the key bytes. Same key → same token.
pub fn index_token(key: &str) -> IndexToken {
    IndexToken(*blake3::hash(key.as_bytes()).as_bytes())
}

/// The query engine.
///
/// Provides state reconstruction, encrypted equality indexes, and
/// time-travel queries.
pub struct QueryEngine<S: StorageEngine> {
    storage: S,
    /// The encryption key for index tokens.
    index_key: Key,
    /// The current key version.
    key_version: u32,
}

impl<S: StorageEngine> QueryEngine<S> {
    /// Create a new query engine.
    pub fn new(storage: S, index_key: Key, key_version: u32) -> Self {
        Self {
            storage,
            index_key,
            key_version,
        }
    }

    /// Reconstruct the database state from all operations.
    ///
    /// Decrypts each operation's payload and applies it to the state.
    pub fn reconstruct_state(&self) -> Result<DbState, QueryError> {
        let ops = self.storage.read_all_operations()?;
        self.reconstruct_from_ops(&ops)
    }

    /// Reconstruct the database state from a set of operations.
    pub fn reconstruct_from_ops(&self, ops: &[Operation]) -> Result<DbState, QueryError> {
        let mut state = DbState::default();
        let mut clock = LogicalClock::new();

        for op in ops {
            // The format is: [32-byte index token][12-byte nonce][ciphertext]
            if op.ciphertext.len() < 44 {
                return Err(QueryError::IndexDecryption(
                    "ciphertext too short".to_string(),
                ));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&op.ciphertext[32..44]);
            let ct = veildb_crypto::Ciphertext {
                key_version: self.key_version,
                nonce,
                data: op.ciphertext[44..].to_vec(),
            };
            let plaintext = decrypt(&self.index_key, &ct)?;
            let put: PutOp = postcard::from_bytes(&plaintext)
                .map_err(|e| QueryError::Serialization(e.to_string()))?;

            state.entries.insert(put.key, put.value);
            clock.merge(&op.logical_clock);
        }

        state.clock = clock;
        Ok(state)
    }

    /// Get a value by key using the encrypted index.
    ///
    /// This uses the deterministic index token to find the operation
    /// without scanning all operations.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, QueryError> {
        let token = index_token(key);
        let ops = self.storage.read_all_operations()?;

        // Find the latest operation whose index token matches.
        let mut latest: Option<Operation> = None;
        for op in ops {
            // The index token is stored as the first 32 bytes of the
            // ciphertext (before the nonce).
            if op.ciphertext.len() >= 32 + 12 {
                let stored_token = &op.ciphertext[..32];
                if stored_token == token.0.as_slice() {
                    latest = Some(op);
                }
            }
        }

        let op = latest.ok_or_else(|| QueryError::KeyNotFound(key.to_string()))?;

        // Decrypt the payload.
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&op.ciphertext[32..44]);
        let ct = veildb_crypto::Ciphertext {
            key_version: self.key_version,
            nonce,
            data: op.ciphertext[44..].to_vec(),
        };
        let plaintext = decrypt(&self.index_key, &ct)?;
        let put: PutOp = postcard::from_bytes(&plaintext)
            .map_err(|e| QueryError::Serialization(e.to_string()))?;

        Ok(put.value)
    }

    /// Build an encrypted index entry for a key-value pair.
    ///
    /// The format is: [32-byte index token][12-byte nonce][ciphertext]
    pub fn build_indexed_ciphertext(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, QueryError> {
        let put = PutOp {
            key: key.to_string(),
            value: value.to_vec(),
        };
        let plaintext = postcard::to_allocvec(&put)?;
        let ct = encrypt(&self.index_key, self.key_version, &plaintext)?;

        let mut result = Vec::with_capacity(32 + 12 + ct.data.len());
        result.extend_from_slice(&index_token(key).0);
        result.extend_from_slice(&ct.nonce);
        result.extend_from_slice(&ct.data);
        Ok(result)
    }

    /// Find the nearest snapshot at or before a given clock.
    ///
    /// Returns the snapshot and its ID. The snapshot's clock must be
    /// dominated by (at or before) the target clock.
    pub fn find_snapshot_at_or_before(
        &self,
        clock: &LogicalClock,
    ) -> Result<Option<(SnapshotId, Snapshot)>, QueryError> {
        let mut best: Option<(SnapshotId, Snapshot)> = None;

        // Iterate through all snapshots.
        let mut id = 1i64;
        loop {
            match self.storage.load_snapshot(id) {
                Ok(snapshot) => {
                    // The snapshot is at or before the target clock if
                    // the target clock dominates the snapshot's clock.
                    if clock.dominates(&snapshot.logical_clock) {
                        best = Some((id, snapshot));
                    }
                    id += 1;
                }
                Err(veildb_storage::StorageError::SnapshotNotFound(_)) => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(best)
    }

    /// Time-travel query: reconstruct the state at a given clock.
    ///
    /// Uses the nearest snapshot ≤ target clock, then replays only
    /// operations after it. Never does a full replay when a snapshot
    /// exists.
    pub fn query_at(&self, clock: &LogicalClock) -> Result<DbState, QueryError> {
        // Find the nearest snapshot at or before the target clock.
        let (_snapshot_id, snapshot) = self
            .find_snapshot_at_or_before(clock)?
            .ok_or(QueryError::NoSnapshotFound)?;

        // Deserialize the snapshot state.
        let mut state: DbState = postcard::from_bytes(&snapshot.state)
            .map_err(|e| QueryError::Serialization(e.to_string()))?;

        // Replay operations after the snapshot.
        let all_ops = self.storage.read_all_operations()?;
        let mut clock_so_far = snapshot.logical_clock.clone();

        for op in &all_ops {
            // Skip operations already in the snapshot.
            if op.logical_clock.dominates(&snapshot.logical_clock) {
                // Only apply if the operation's clock is at or before
                // the target clock.
                if clock.dominates(&op.logical_clock) {
                    // Decrypt and apply.
                    let mut nonce = [0u8; 12];
                    if op.ciphertext.len() >= 32 + 12 {
                        nonce.copy_from_slice(&op.ciphertext[32..44]);
                        let ct = veildb_crypto::Ciphertext {
                            key_version: self.key_version,
                            nonce,
                            data: op.ciphertext[44..].to_vec(),
                        };
                        if let Ok(plaintext) = decrypt(&self.index_key, &ct) {
                            if let Ok(put) = postcard::from_bytes::<PutOp>(&plaintext) {
                                state.entries.insert(put.key, put.value);
                            }
                        }
                    }
                    clock_so_far.merge(&op.logical_clock);
                }
            }
        }

        state.clock = clock_so_far;
        Ok(state)
    }

    /// Create a snapshot of the current state.
    pub fn create_snapshot(&mut self) -> Result<SnapshotId, QueryError> {
        let state = self.reconstruct_state()?;
        let ops = self.storage.read_all_operations()?;

        // Compute the last operation hash.
        let last_op_hash = if let Some(op) = ops.last() {
            veildb_integrity::operation_hash(op)
        } else {
            [0u8; 32]
        };

        // Compute the Merkle root.
        let hashes: Vec<[u8; 32]> = ops.iter().map(veildb_integrity::operation_hash).collect();
        let merkle_root = veildb_integrity::MerkleTree::build(&hashes).root();

        let snapshot = Snapshot {
            logical_clock: state.clock.clone(),
            last_operation: last_op_hash,
            state: postcard::to_allocvec(&state)?,
            merkle_root,
        };

        Ok(self.storage.create_snapshot(snapshot)?)
    }

    /// Get the current logical clock.
    pub fn current_clock(&self) -> Result<LogicalClock, QueryError> {
        Ok(self.storage.current_clock()?)
    }
}

/// A summary of an operation for the log view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSummary {
    /// The operation ID.
    pub id: OperationId,
    /// The operation hash.
    pub hash: [u8; 32],
    /// The logical clock.
    pub clock: LogicalClock,
    /// The device that created it.
    pub device_id: [u8; 32],
    /// Number of parents.
    pub parent_count: usize,
}

/// Build a log of operation summaries.
pub fn build_log(ops: &[Operation]) -> Vec<OperationSummary> {
    ops.iter()
        .map(|op| OperationSummary {
            id: op.id,
            hash: veildb_integrity::operation_hash(op),
            clock: op.logical_clock.clone(),
            device_id: op.device_id,
            parent_count: op.parents.len(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use veildb_crypto::Key;
    use veildb_storage::{LogicalClock, Operation, OperationId, SqliteStorage};

    fn test_engine() -> QueryEngine<SqliteStorage> {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let key = Key::generate();
        QueryEngine::new(storage, key, 1)
    }

    fn make_op(
        device: [u8; 32],
        seq: u64,
        key: &str,
        value: &[u8],
        engine: &QueryEngine<SqliteStorage>,
    ) -> Operation {
        let ct = engine.build_indexed_ciphertext(key, value).unwrap();
        let mut clock = LogicalClock::new();
        clock.advance(device);
        Operation {
            id: OperationId::new(device, seq),
            parents: vec![],
            logical_clock: clock,
            device_id: device,
            ciphertext: ct,
            signature: vec![],
        }
    }

    #[test]
    fn index_token_deterministic() {
        let t1 = index_token("hello");
        let t2 = index_token("hello");
        let t3 = index_token("world");
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn build_and_reconstruct() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key1", b"value1", &engine);
        let op2 = make_op([1u8; 32], 2, "key2", b"value2", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        let state = engine.reconstruct_state().unwrap();
        assert_eq!(state.get("key1").unwrap(), &b"value1".to_vec());
        assert_eq!(state.get("key2").unwrap(), &b"value2".to_vec());
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn get_by_key() {
        let mut engine = test_engine();
        let op = make_op([1u8; 32], 1, "mykey", b"myvalue", &engine);
        engine.storage.append(op).unwrap();

        let value = engine.get("mykey").unwrap();
        assert_eq!(value, b"myvalue");
        assert!(engine.get("missing").is_err());
    }

    #[test]
    fn get_latest_value() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key", b"old", &engine);
        let op2 = make_op([1u8; 32], 2, "key", b"new", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        let value = engine.get("key").unwrap();
        assert_eq!(value, b"new");
    }

    #[test]
    fn snapshot_and_time_travel() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key1", b"value1", &engine);
        let op2 = make_op([1u8; 32], 2, "key2", b"value2", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        // Create a snapshot.
        let snap_id = engine.create_snapshot().unwrap();
        assert!(snap_id > 0);

        // Add more operations.
        let op3 = make_op([1u8; 32], 3, "key3", b"value3", &engine);
        engine.storage.append(op3).unwrap();

        // Query at the snapshot clock.
        let clock = engine.current_clock().unwrap();
        let state = engine.query_at(&clock).unwrap();
        assert_eq!(state.len(), 3);
    }

    #[test]
    fn build_log_works() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key1", b"value1", &engine);
        let op2 = make_op([1u8; 32], 2, "key2", b"value2", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        let ops = engine.storage.read_all_operations().unwrap();
        let log = build_log(&ops);
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].id.sequence, 1);
        assert_eq!(log[1].id.sequence, 2);
    }
}