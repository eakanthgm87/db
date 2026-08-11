### Step 1: Initialize a New Database

1. In the __Database Path__ field, enter a path like `C:\Users\ADMIN\Downloads\nem\my-database.vdb`
2. Enter a strong __Passphrase__ (this encrypts your database)
3. Click __Init__ to create a new encrypted database

__OR__

### Step 2: Open an Existing Database

1. Browse to an existing `.vdb` file
2. Enter the passphrase used when creating it
3. Click __Open__

## Dashboard Features (Once Connected)

After initialization/opening, the dashboard will display:

### Main Views

- __Dashboard__ - Overview showing:

  - Database status and operation count
  - Merkle root hash (integrity verification)
  - Device count and sync status
  - Latest snapshot info

- __Data Browser__ - Key-value interface:

  - __Put__: Add key-value pairs (encrypted)
  - __Get__: Retrieve values by key
  - View operation log

- __Devices__ - Device management:

  - List trusted devices
  - Trust new devices (requires public key)
  - Revoke device access

- __Sync__ - Synchronization:

  - Sync with LAN peers
  - View sync reports
  - Monitor operation transfer

- __Time Travel__ - Historical queries:

  - Query database state at specific logical clocks
  - View snapshots

- __Backup/Restore__ - Data safety:

  - Create encrypted backups
  - Restore from backup files

## Security Notes

⚠️ __Important:__

- Your passphrase cannot be recovered if lost
- All data is encrypted locally
- The server (if used for sync) never sees plaintext
- Keep backups secure

## Current Limitation

The frontend is functional but currently depends on the Tauri backend. To fully use it:

1. Ensure the Rust backend compiles (`cargo check --workspace`)
2. Run via `cd bindings && cargo tauri dev` (requires Tauri CLI installed)

__To install Tauri CLI:__

```bash
cargo install tauri-cli --version "^2.0.0"
```

## Quick Test

Try this workflow:

1. Click __Init__ with a path and passphrase
2. Once open, use the __Put__ command to add test data
3. Use __Get__ to retrieve it
4. Check __Dashboard__ for status
5. Use __Backup__ to export encrypted backup
