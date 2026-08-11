# VeilDB

Privacy-first, local-first, zero-trust embedded database written in Rust.

## Overview

VeilDB is a local-first, end-to-end encrypted embedded database. It uses SQLite (via `rusqlite`) as the physical storage engine, with all data encrypted at rest using AES-256-GCM. Every operation is hashed (BLAKE3) and signed (Ed25519), forming a multi-parent Merkle DAG for cryptographic integrity verification.

## Key Features

- **Local-first**: Local storage is authoritative; sync is async and optional
- **Zero-trust**: Servers only hold opaque ciphertext
- **Cryptographic integrity**: BLAKE3 + Merkle DAG tamper detection
- **Immutable history**: Append-only operations, always reconstructible
- **Deterministic sync**: Commutative/associative/idempotent CRDT merge
- **Time travel**: Query any historical state via snapshot + replay
- **Device-based trust**: Bootstrap, approval, and revocation
- **Fine-grained sharing**: Hierarchical key wrapping (Master → Collection → Record)
- **Encrypted backup/restore**: Full validation on restore

## Workspace Structure

```
veildb/
├── crates/
│   ├── storage/     # SQLite persistence only
│   ├── crypto/      # AES-GCM, Ed25519, X25519, Argon2, BLAKE3 wiring
│   ├── integrity/   # hashing, Merkle DAG, proofs, tamper detection
│   ├── sync/        # CRDT merge, peer protocol, transports
│   ├── query/       # encrypted indexes, logical clock, time travel
│   ├── access/      # device trust, revocation, sharing, backup/restore
│   └── core/        # VeilDbCore facade — the ONLY app-facing API
├── cli/             # clap CLI, depends only on core
├── bindings/        # Tauri commands, depends only on core
└── frontend/        # React + TS + Tailwind, talks only to bindings
```

## Build

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features
```

## CLI Usage

```bash
veildb init <path>                    # Initialize a new database
veildb put <key> <value>              # Write a value
veildb get <key>                      # Read a value
veildb sync --backend lan             # Sync with peers
veildb verify                         # Verify integrity
veildb log [--at <clock>]             # View operation log / time travel
veildb device trust <pubkey>          # Trust a new device
veildb device revoke <device-id>      # Revoke a device
veildb share <key> --to <device-id>   # Share a key with a device
veildb backup <output>                # Encrypted backup
veildb restore <archive>              # Restore from backup
```

## License

MIT OR Apache-2.0