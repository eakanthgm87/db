# VeilDB — Master Project Build Specification

## 0. Tech Stack (authoritative)

| Layer | Technology |
|---|---|
| Language | Rust (workspace, edition 2021+) |
| Storage engine | `rusqlite` + SQLite (file-based, WAL mode) |
| Encryption | `aes-gcm` (AES-256-GCM) |
| Signatures | `ed25519-dalek` |
| Key exchange | `x25519-dalek` |
| Password KDF | `argon2` |
| CSPRNG | `rand_core` / `OsRng` |
| Key zeroization | `zeroize` |
| Hashing | `blake3` |
| Canonical serialization | `postcard` |
| Sync transport (LAN) | `tokio` + plain TCP/WebSocket |
| Sync transport (future) | Cloud relay / `libp2p` (feature-gated stubs) |
| Errors | `thiserror` (per-crate) + `anyhow` (app boundary) |
| CLI | `clap` + `anyhow` |
| Bindings | `tauri` v2 (commands) |
| Frontend | React + TypeScript + Tailwind CSS |
| Testing | `cargo test`, `proptest`, `criterion` (benches) |

No custom crypto. No Sled. No Postgres. No HTTP APIs unless explicitly required later.

---

## 1. Project Objective

Build **VeilDB**: a privacy-first, local-first, zero-trust embedded database written primarily in Rust, using **SQLite (via `rusqlite`)** as the sole physical storage engine.

Required capabilities:
- Local-first, fully offline reads/writes
- End-to-end encryption (server never sees plaintext or keys)
- Zero-trust synchronization
- Cryptographically verifiable integrity (BLAKE3 + Merkle DAG)
- Append-only, immutable operation history with multi-parent DAG (not a single linear hash chain)
- Deterministic, commutative/associative/idempotent CRDT merge
- Time-travel queries via snapshot + replay
- Device-based identity, trust, and revocation
- Fine-grained per-record encrypted sharing
- Encrypted backup/restore
- Pluggable sync backends (Mock, LAN now; Cloud, P2P stubbed)
- CLI (clap) and Tauri + React frontend, both driven only through a single `core` facade

Networking is optional; the database is fully usable offline.

---

## 2. Core Design Principles

1. **Local-first** — local storage is authoritative; sync is async and optional.
2. **Zero-trust server** — servers only ever hold opaque ciphertext; compromise reveals nothing.
3. **Cryptographic integrity** — every operation is hashed (BLAKE3) and signed (Ed25519); Merkle trees make tampering detectable.
4. **Immutable history** — operations are never mutated, only appended; state is always reconstructible.
5. **Deterministic sync** — merge is commutative, associative, idempotent; all trusted devices converge to identical state.
6. **Separation of concerns** — see dependency graph in §4. CLI/frontend talk only to `core`.
7. **No custom cryptography** — only established, audited Rust crates.

---

## 3. Workspace Structure

```text
veildb/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── .gitignore
├── rust-toolchain.toml
│
├── crates/
│   ├── storage/     # SQLite persistence only
│   ├── crypto/      # AES-GCM, Ed25519, X25519, Argon2, BLAKE3 wiring
│   ├── integrity/   # hashing, Merkle DAG, proofs, tamper detection
│   ├── sync/        # CRDT merge, peer protocol, transports
│   ├── query/       # encrypted indexes, logical clock, time travel
│   ├── access/      # device trust, revocation, sharing, backup/restore
│   └── core/        # VeilDbCore facade — the ONLY app-facing API
│
├── cli/             # clap CLI, depends only on core
├── bindings/         # Tauri commands, depends only on core
├── frontend/         # React + TS + Tailwind, talks only to bindings
│
├── tests/
├── benches/
├── migrations/
├── docs/
└── scripts/
```

Must build clean with:
```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features
```

---

## 4. Dependency Graph

```text
storage ──────────────► integrity
crypto ────┬──────────► access
           └──────────► query
storage + crypto + integrity ──► sync
storage + crypto + integrity + sync + query + access ──► core
core ──► cli
core ──► bindings ──► frontend (via Tauri IPC only)
```

Rules:
- `storage` depends on nothing else in the workspace (no crypto/sync/query/access).
- `crypto` depends on no application-level crate.
- `integrity` may use `storage` types (operation shape) but doesn't touch SQLite directly.
- `sync` is the **only** crate allowed to cross a network boundary.
- `cli` and `bindings` depend **only** on `core` — no direct storage/crypto/sync access.
- Frontend JS/TS talks **only** through Tauri bindings — no direct filesystem, DB, network, or crypto access.

---

## 5. Storage Engine (SQLite / rusqlite)

`storage` is the physical persistence layer — SQLite is an implementation detail, never leaked through the public API. Everything else talks to it via the `StorageEngine` trait.

Manages: DB lifecycle, migrations, append-only operations, snapshots, metadata, transactions, crash recovery, safe compaction, encrypted blob persistence.

Must never: decrypt data, generate keys, verify signatures, CRDT-merge, or touch the network.

### Schema

```sql
CREATE TABLE operations (
    operation_id       BLOB PRIMARY KEY,
    device_id          BLOB NOT NULL,
    sequence_number     INTEGER NOT NULL,
    logical_clock       BLOB NOT NULL,
    parents             BLOB NOT NULL,
    operation_hash       BLOB NOT NULL,
    ciphertext           BLOB NOT NULL,
    signature             BLOB NOT NULL,
    UNIQUE(device_id, sequence_number)
);

CREATE TABLE snapshots (
    snapshot_id     INTEGER PRIMARY KEY,
    logical_clock    BLOB NOT NULL,
    last_operation    BLOB NOT NULL,
    state              BLOB NOT NULL,
    merkle_root         BLOB NOT NULL
);

CREATE TABLE devices (
    device_id           BLOB PRIMARY KEY,
    public_key           BLOB NOT NULL,
    trusted               INTEGER NOT NULL,
    approved_by            BLOB,
    approval_signature      BLOB,
    created_at              INTEGER NOT NULL
);

CREATE TABLE metadata (
    key    TEXT PRIMARY KEY,
    value  BLOB NOT NULL
);
```

Use WAL journal mode + `synchronous=NORMAL` (documented in `docs/storage-format.md`), transactions for every atomic op, no partial commits.

### Storage API

```rust
pub trait StorageEngine {
    fn append(&mut self, operation: Operation) -> Result<[u8; 32], StorageError>;
    fn read_operations(&self, ids: &[OperationId]) -> Result<Vec<Operation>, StorageError>;
    fn read_all_operations(&self) -> Result<Vec<Operation>, StorageError>;
    fn latest_operation_hash(&self) -> Result<Option<[u8; 32]>, StorageError>;
    fn create_snapshot(&mut self, snapshot: Snapshot) -> Result<SnapshotId, StorageError>;
    fn load_snapshot(&self, id: SnapshotId) -> Result<Snapshot, StorageError>;
    fn compact(&mut self, snapshot: SnapshotId) -> Result<(), StorageError>;
}
```

---

## 6. Operation Model

```rust
pub struct OperationId {
    pub device_id: [u8; 32],
    pub sequence: u64,
}

pub struct Operation {
    pub id: OperationId,
    pub parents: Vec<[u8; 32]>,      // multi-parent DAG, not a linear chain
    pub logical_clock: LogicalClock,
    pub device_id: [u8; 32],
    pub ciphertext: Vec<u8>,          // opaque to storage/integrity/sync
    pub signature: Vec<u8>,
}
```

Each device keeps its own monotonic sequence: `(A,1)(A,2)(A,3)…`, `(B,1)(B,2)(B,3)…` — globally distinguishable, independently created, converge via CRDT merge.

---

## 7. Crypto Layer

Sole owner of: AES-GCM, Ed25519, X25519, Argon2, CSPRNG, zeroization.

```rust
pub struct Key { /* zeroized 32-byte key */ }
pub struct Ciphertext {
    pub key_version: u32,
    pub nonce: [u8; 12],   // fresh CSPRNG nonce every call, never reused per key
    pub data: Vec<u8>,
}
```

Every device: Ed25519 keypair (signing) + X25519 material (key exchange). Private keys never cross the public API. Every ciphertext carries a `key_version`; rotation never invalidates historical data.

---

## 8. Integrity Layer

BLAKE3 hashing, operation-hash calc, Merkle DAG (multi-parent, not linear `prev_hash`), proofs, diffing, tamper audit.

Operation hash = BLAKE3 over canonical `postcard` serialization of `(id, parents, logical_clock, device_id, ciphertext, signature)`.

```rust
pub struct MerkleTree { pub root: [u8; 32] }
// build() / root() / diff() / generate_proof() / verify_proof()
```

Merkle diff lets sync find missing operations without transferring the whole DB.

---

## 9. Query Layer

Encrypted equality indexes (BLAKE3-normalize plaintext → deterministic AEAD token — documented leakage: same value → same token → equality search possible, an explicit tradeoff), logical clock (no wall-clock timestamps for conflict resolution), state reconstruction, time travel.

Time travel: find nearest snapshot ≤ target clock → load → replay only operations after it → never full replay when a snapshot exists.

---

## 10. Sync Engine

Only crate allowed to cross the network. Custom operation-based CRDT satisfying:

```text
merge(A,B) == merge(B,A)                    # commutative
merge(merge(A,B),C) == merge(A,merge(B,C))  # associative
merge(A,A) == A                              # idempotent
```

No timestamp-based conflict resolution.

### Sync protocol
```text
1. Authenticate peer          8. Verify operation hashes
2. Verify device trust        9. Verify signatures
3. Exchange DB metadata       10. Validate operation graph
4. Exchange Merkle roots      11. CRDT merge
5. Diff subtrees              12. Apply atomically
6. Identify missing ops       13. Update local Merkle state
7. Transfer ciphertext+meta   14. Commit SQLite transaction
```
Partial transfers must never leave invalid committed state.

Backends: `MockBackend`, `LanBackend` now; `CloudBackend`, `P2pBackend` feature-gated stubs. Sync engine is transport-agnostic.

---

## 11. Access Control

Device trust: first device bootstraps and self-trusts as root; every subsequent device is approved by an already-trusted device (signed approval) — a device may never approve itself. Revocation immediately invalidates future sync authorization.

Sharing: never share the whole master key — hierarchical `Master Key → Collection Key → Record Key`; sharing wraps a record/collection key for the target device only.

Backup: encrypted archive + metadata (`db id`, format version, key-version info, Merkle root, snapshot metadata). Restore: authenticate/decrypt → validate structure → validate crypto integrity → compare Merkle root → validate operations → atomic restore. No partially-restored state ever exposed.

---

## 12. Core Facade — Endpoint Wiring

`VeilDbCore` is the **only** application-facing API. Every CLI command and every Tauri command maps 1:1 to one of these; no business logic lives outside `core`.

```rust
pub struct VeilDbCore { /* internal: storage, crypto, integrity, sync, query, access */ }

impl VeilDbCore {
    pub fn init(path: &Path, passphrase: SecretString) -> Result<Self, CoreError>;
    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<OperationId, CoreError>;
    pub fn get(&self, key: &str) -> Result<Vec<u8>, CoreError>;
    pub async fn sync(&mut self, backend: SyncBackend) -> Result<SyncReport, CoreError>;
    pub fn verify_integrity(&self) -> Result<IntegrityStatus, CoreError>;
    pub fn query_at(&self, clock: LogicalClock) -> Result<DbState, CoreError>;
    pub fn log(&self, at: Option<LogicalClock>) -> Result<Vec<OperationSummary>, CoreError>;
    pub fn trust_device(&mut self, public_key: &[u8]) -> Result<TrustEntry, CoreError>;
    pub fn revoke_device(&mut self, device_id: &[u8]) -> Result<(), CoreError>;
    pub fn share(&mut self, key: &str, to_device: &[u8]) -> Result<ReEncryptedBlob, CoreError>;
    pub fn backup(&self, output: &Path) -> Result<EncryptedArchive, CoreError>;
    pub fn restore(&mut self, archive: &Path) -> Result<(), CoreError>;
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>, CoreError>;
    pub fn status(&self) -> Result<DbStatus, CoreError>; // op count, merkle root, snapshot info
}
```

Never exposes: storage internals, SQLite connections, raw keys.

### Write path
`put()` → validate → generate `OperationId` → encrypt → build canonical `Operation` → sign → hash → single SQLite transaction (append op + update index + update metadata + update integrity state) → commit. No partial write ever visible.

### Read path
`get()` → query encrypted index → locate operation/state → read ciphertext → `crypto.decrypt()` → return plaintext.

### CLI ⇄ Core mapping

| CLI command | Core method |
|---|---|
| `veildb init` | `init` |
| `veildb put <key> <value>` | `put` |
| `veildb get <key>` | `get` |
| `veildb sync --backend lan` | `sync` |
| `veildb verify` | `verify_integrity` |
| `veildb log` / `veildb log --at <clock>` | `log` / `query_at` |
| `veildb device trust <pubkey>` | `trust_device` |
| `veildb device revoke <device-id>` | `revoke_device` |
| `veildb share <key> --to <device-id>` | `share` |
| `veildb backup <output>` | `backup` |
| `veildb restore <archive>` | `restore` |

Exit codes: `0` success · `1` general error · `2` integrity/tamper failure. Passphrase via interactive secure prompt only — never left in shell history.

### Tauri command ⇄ Core mapping

| Tauri command | Core method |
|---|---|
| `vdb_init` | `init` |
| `vdb_put` | `put` |
| `vdb_get` | `get` |
| `vdb_sync` | `sync` |
| `vdb_verify` | `verify_integrity` |
| `vdb_query_at` | `query_at` |
| `vdb_list_devices` | `list_devices` |
| `vdb_trust_device` | `trust_device` |
| `vdb_revoke_device` | `revoke_device` |
| `vdb_backup` | `backup` |
| `vdb_restore` | `restore` |

All errors crossing the Tauri boundary are serializable (`CoreError` → JSON). Never expose private/master keys, raw key material, SQLite connections, or internal storage structures across IPC.

---

## 13. Frontend (React + TS + Tailwind, via Tauri)

Views and the data each pulls (all via `vdb_*` commands, never direct access):

- **Dashboard** — DB status, operation count, latest snapshot, Merkle root, integrity status (`VERIFIED` / `TAMPERED` / `UNVERIFIED` with distinct visual treatment), device count, last sync time.
- **Devices** — list (`vdb_list_devices`), trust new device (`vdb_trust_device`), revoke (`vdb_revoke_device`).
- **Sync Status** — trigger sync (`vdb_sync`), live progress through the 14-step protocol, last `SyncReport`.
- **Time Travel** — logical-clock/date picker → `vdb_query_at` → render historical `DbState`.
- **Tamper Test** (developer-mode only, gated, disabled in production builds) — corrupt local ciphertext/hash → `vdb_verify` → show detected tamper.
- **Backup / Restore** — `vdb_backup` / `vdb_restore` with progress and validation-step feedback.

No `localStorage`/`sessionStorage` for DB state — React state only. No direct filesystem/network/crypto access from frontend code.

---

## 14. Error Handling

Per-crate typed errors via `thiserror`: `StorageError`, `CryptoError`, `IntegrityError`, `SyncError`, `QueryError`, `AccessError`, `CoreError`. `anyhow` only at CLI/app boundary. No `unwrap()`/`expect()` in production paths except statically-guaranteed invariants, explicitly documented.

---

## 15. Testing Strategy

- **Unit tests** in every crate; **workspace integration tests** in `tests/`.
- **Storage**: append/read/transactions/crash recovery/snapshot/compaction/duplicate detection.
- **Crypto**: encrypt-decrypt, tamper detection, nonce uniqueness, signatures, wrong key/pubkey, key rotation, Argon2 determinism.
- **Integrity**: deterministic hashes, Merkle root/diff/proof gen+verify, tamper detection.
- **Sync**: commutativity/associativity/idempotency, offline divergence, merge convergence, duplicate ops, dropped connections, untrusted devices.
- **Query**: deterministic index tokens, equality queries, index rebuild, snapshot reconstruction, time travel, out-of-order ops.
- **Access**: bootstrap, approval, self-approval rejection, revocation, sharing, backup/restore, corrupted backup.
- **Core**: full lifecycle — init → write → read → snapshot → 2nd device → offline writes → sync → merge → verify → time travel → backup → restore → verify again.
- **Property tests** (`proptest`): CRDT laws (commutative/associative/idempotent), serialize↔deserialize round-trip, snapshot↔restore round-trip.
- **Crash tests**: fault injection at each SQLite transaction phase (before/during/after insert, before/after commit) + restart + verify no partial writes/broken index/corrupt snapshot/inconsistent metadata.
- **Benchmarks** (`criterion`) at 10k/100k/1M ops: append/read/encryption throughput, Merkle root gen, Merkle diff, CRDT merge, snapshot creation, restore, startup. Baseline first, no premature optimization.

---

## 16. Documentation (`docs/`)

```text
docs/
├── architecture.md
├── security-model.md
├── storage-format.md
├── cryptography.md
├── sync-protocol.md
├── threat-model.md
└── decisions/
    ├── 001-storage-engine.md
    ├── 002-operation-model.md
    └── 003-encryption-model.md
```
Must cover: architecture, dependency graph, threat model, trust assumptions, encryption boundaries, operation model, CRDT algorithm, Merkle structure, SQLite schema, snapshot format, sync protocol, key rotation, backup format, known limitations.

---

## 17. Threat Model

**Protects against**: compromised sync server, stolen encrypted backup, unauthorized device, malicious DB modification, corrupted operation/payload, replayed operation, invalid signature, revoked device.

**Does NOT protect against**: fully compromised trusted device, attacker with unlocked keys, malicious code inside a trusted process, compromised OS, side-channel attacks, denial of service.

---

## 18. Hard Restrictions

No traditional server-side DB · no Postgres as central authority · no authoritative cloud server · no plaintext data or keys stored remotely · no wall-clock-based conflict resolution · no single linear global hash chain · no SQLite leakage outside `storage` · no exposed private keys · no business logic in CLI or React · no frontend bypass of `core` · no `localStorage` as DB · no custom crypto · no unnecessary deps · no HTTP APIs unless later required.

---

## 19. Implementation Order

1. Workspace + `storage` + `crypto` (compiling, tested)
2. `integrity` (hashes, operation verification, Merkle DAG + proofs)
3. `query` (encrypted equality indexes, state reconstruction)
4. `access` (trust, revocation, sharing, backup/restore)
5. `sync` (operation exchange, Merkle diff, CRDT merge, `MockBackend` before real transports)
6. `core` (compose all six behind `VeilDbCore`)
7. `cli` (entirely on `core`)
8. `bindings` + Tauri + React (only after `core` integration tests pass)

---

## 20. Definition of Done

`cargo test --workspace` passes · `cargo clippy --workspace --all-targets --all-features` passes clean · and the full two-device lifecycle works end-to-end: create → write → snapshot → offline continue on Device A; new identity → get authorized → offline write on Device B; sync (authenticate → Merkle diff → transfer → verify sigs → CRDT merge → atomic commit) → same logical state on both → verify integrity → time travel → backup → restore → verify again.

Storage engine must be swappable later without touching crypto, integrity, sync, query, access, core, CLI, or frontend. Prioritize correctness, security, determinism, clear abstractions, and testability over premature performance optimization.
