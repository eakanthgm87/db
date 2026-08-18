// Mock API layer for VeilDB frontend.
//
// When running inside the Tauri webview, this delegates to the real
// Tauri `invoke` commands. When running in a plain browser (e.g.
// `npm run dev`), it provides an in-memory mock so the UI is fully
// functional for development and demonstration.

import { invoke } from "@tauri-apps/api/core";

// Detect whether we're running inside the Tauri webview.
function isTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    "__TAURI_INTERNALS__" in window
  );
}

// ---------------------------------------------------------------------------
// In-memory mock state
// ---------------------------------------------------------------------------

interface MockDevice {
  device_id: string;
  public_key: string;
  trusted: boolean;
  approved_by: string | null;
  created_at: number;
}

interface MockOperation {
  sequence: number;
  device_id: string;
  hash: string;
  parent_count: number;
  clock: string[];
}

interface MockState {
  path: string | null;
  passphrase: string | null;
  data: Map<string, string>;
  devices: MockDevice[];
  operations: MockOperation[];
  merkleRoot: string;
  snapshotId: number | null;
  snapshotMerkleRoot: string | null;
  keyVersion: number;
  formatVersion: number;
  selfDeviceId: string;
  selfPublicKey: string;
  dbId: string;
  lastSync: string | null;
}

let mock: MockState | null = null;

function randomHex(len: number): string {
  const chars = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * 16)];
  }
  return out;
}

function mockInit(path: string, passphrase: string): any {
  if (mock && mock.path === path) {
    throw new Error("Database already exists");
  }
  const selfDeviceId = randomHex(64);
  const selfPublicKey = randomHex(64);
  mock = {
    path,
    passphrase,
    data: new Map(),
    devices: [
      {
        device_id: selfDeviceId,
        public_key: selfPublicKey,
        trusted: true,
        approved_by: null,
        created_at: Date.now(),
      },
    ],
    operations: [],
    merkleRoot: randomHex(64),
    snapshotId: null,
    snapshotMerkleRoot: null,
    keyVersion: 1,
    formatVersion: 1,
    selfDeviceId,
    selfPublicKey,
    dbId: randomHex(64),
    lastSync: null,
  };
  return {
    db_id: mock.dbId,
    device_id: mock.selfDeviceId,
    key_version: mock.keyVersion,
  };
}

function mockOpen(path: string, passphrase: string): any {
  if (!mock || mock.path !== path) {
    throw new Error(`Database not found: ${path}`);
  }
  if (mock.passphrase !== passphrase) {
    throw new Error("Invalid passphrase");
  }
  return {
    db_id: mock.dbId,
    device_id: mock.selfDeviceId,
    key_version: mock.keyVersion,
  };
}

function mockClose(): void {
  mock = null;
}

function mockPut(key: string, value: string): any {
  requireMock();
  const seq = mock!.operations.length + 1;
  mock!.data.set(key, value);
  mock!.operations.push({
    sequence: seq,
    device_id: mock!.selfDeviceId,
    hash: randomHex(64),
    parent_count: seq > 1 ? 1 : 0,
    clock: [`${mock!.selfDeviceId}:${seq}`],
  });
  mock!.merkleRoot = randomHex(64);
  return { device_id: mock!.selfDeviceId, sequence: seq };
}

function mockGet(key: string): string {
  requireMock();
  const val = mock!.data.get(key);
  if (val === undefined) {
    throw new Error(`Key not found: ${key}`);
  }
  return val;
}

function mockStatus(): any {
  requireMock();
  return {
    db_id: mock!.dbId,
    operation_count: mock!.operations.length,
    merkle_root: mock!.merkleRoot,
    logical_clock: mock!.operations.map(
      (o) => `${o.device_id}:${o.sequence}`
    ),
    latest_snapshot_id: mock!.snapshotId,
    snapshot_merkle_root: mock!.snapshotMerkleRoot,
    device_count: mock!.devices.length,
    self_device_id: mock!.selfDeviceId,
    self_public_key: mock!.selfPublicKey,
    key_version: mock!.keyVersion,
    format_version: mock!.formatVersion,
    bootstrapped: true,
  };
}

function mockVerify(): any {
  requireMock();
  return { status: "VERIFIED", verified: true };
}

function mockQueryAt(clock: string): any {
  requireMock();
  const entries = Array.from(mock!.data.entries()).map(([k, v]) => ({
    key: k,
    value: v,
  }));
  return {
    clock: [clock],
    entries,
  };
}

function mockLog(): any {
  requireMock();
  return { operations: mock!.operations };
}

function mockListDevices(): any {
  requireMock();
  return { devices: mock!.devices };
}

function mockTrustDevice(publicKey: string): any {
  requireMock();
  const deviceId = randomHex(64);
  const device: MockDevice = {
    device_id: deviceId,
    public_key: publicKey,
    trusted: true,
    approved_by: mock!.selfDeviceId,
    created_at: Date.now(),
  };
  mock!.devices.push(device);
  return { device_id: deviceId, trusted: true };
}

function mockRevokeDevice(deviceId: string): void {
  requireMock();
  const dev = mock!.devices.find((d) => d.device_id === deviceId);
  if (dev) {
    dev.trusted = false;
  }
}

function mockBackup(output: string): any {
  requireMock();
  return {
    format_version: mock!.formatVersion,
    db_id: mock!.dbId,
    merkle_root: mock!.merkleRoot,
    path: output,
  };
}

function mockRestore(archive: string): void {
  requireMock();
  // In the mock, restore just re-validates the archive path.
  if (!archive) {
    throw new Error("Invalid archive path");
  }
}

function mockSnapshot(): number {
  requireMock();
  mock!.snapshotId = (mock!.snapshotId ?? 0) + 1;
  mock!.snapshotMerkleRoot = mock!.merkleRoot;
  return mock!.snapshotId;
}

function mockSyncLan(addr: string): any {
  requireMock();
  mock!.lastSync = new Date().toISOString();
  return {
    operations_received: 0,
    operations_sent: mock!.operations.length,
    operations_merged: 0,
    merkle_root: mock!.merkleRoot,
    success: true,
    message: `Mock sync with ${addr} completed`,
  };
}

function mockRotateKey(): any {
  requireMock();
  mock!.keyVersion += 1;
  return { key_version: mock!.keyVersion };
}

function mockGetDag(): any {
  requireMock();
  const nodes = mock!.operations.map((op) => ({
    id: `${op.device_id.slice(0, 8)}...:${op.sequence}`,
    device_id: op.device_id,
    sequence: op.sequence,
    hash: op.hash,
    parents: op.parent_count > 0 ? [mock!.operations[op.sequence - 2]?.hash || ""] : [],
    signature_status: "SIGNED",
    clock: op.clock,
  }));
  const edges: { from: string; to: string }[] = [];
  for (let i = 1; i < nodes.length; i++) {
    edges.push({ from: nodes[i - 1].hash, to: nodes[i].hash });
  }
  return { nodes, edges };
}

function mockGetMerkleTree(): any {
  requireMock();
  const leaves = mock!.operations.map((op, i) => ({
    id: `leaf_${i}`,
    hash: op.hash,
    level: 0,
    index: i,
    is_leaf: true,
  }));
  const internal_nodes: any[] = [];
  let level = 0;
  let current = leaves.map((l) => l.hash);
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const h = randomHex(64);
      internal_nodes.push({
        id: `node_${level}_${i / 2}`,
        hash: h,
        level: level + 1,
        index: i / 2,
        is_leaf: false,
      });
      next.push(h);
    }
    current = next;
    level++;
  }
  return {
    root: mock!.merkleRoot,
    leaves,
    internal_nodes,
  };
}

function mockDevCorruptOperation(deviceId: string, sequence: number): void {
  requireMock();
  const op = mock!.operations.find(
    (o) => o.device_id === deviceId && o.sequence === sequence
  );
  if (!op) {
    throw new Error("Operation not found");
  }
  op.hash = randomHex(64);
  mock!.merkleRoot = randomHex(64);
}

function requireMock(): void {
  if (!mock) {
    throw new Error("Database not initialized or opened");
  }
}

// ---------------------------------------------------------------------------
// Public API — delegates to Tauri or mock
// ---------------------------------------------------------------------------

export interface ApiResult<T> {
  success: boolean;
  data?: T;
  error?: { message: string; code?: number; is_integrity: boolean };
}

function ok<T>(data: T): ApiResult<T> {
  return { success: true, data };
}

function err(message: string, isIntegrity = false): ApiResult<never> {
  return {
    success: false,
    error: { message, is_integrity: isIntegrity },
  };
}

async function call<T>(cmd: string, args: Record<string, unknown>): Promise<ApiResult<T>> {
  if (isTauri()) {
    try {
      const result = await invoke<ApiResult<T>>(cmd, args);
      return result;
    } catch (e: any) {
      return err(e.message || String(e));
    }
  }
  // Browser mock mode.
  try {
    switch (cmd) {
      case "vdb_init":
        return ok(mockInit(args.path as string, args.passphrase as string) as T);
      case "vdb_open":
        return ok(mockOpen(args.path as string, args.passphrase as string) as T);
      case "vdb_close":
        return ok(mockClose() as T);
      case "vdb_put":
        return ok(mockPut(args.key as string, args.value as string) as T);
      case "vdb_get":
        return ok(mockGet(args.key as string) as T);
      case "vdb_status":
        return ok(mockStatus() as T);
      case "vdb_verify":
        return ok(mockVerify() as T);
      case "vdb_query_at":
        return ok(mockQueryAt(args.clock as string) as T);
      case "vdb_log":
        return ok(mockLog() as T);
      case "vdb_list_devices":
        return ok(mockListDevices() as T);
      case "vdb_trust_device":
        return ok(mockTrustDevice((args.publicKey ?? args.public_key) as string) as T);
      case "vdb_revoke_device":
        return ok(mockRevokeDevice((args.deviceId ?? args.device_id) as string) as T);
      case "vdb_backup":
        return ok(mockBackup(args.output as string) as T);
      case "vdb_restore":
        return ok(mockRestore(args.archive as string) as T);
      case "vdb_snapshot":
        return ok(mockSnapshot() as T);
      case "vdb_sync_lan":
        return ok(mockSyncLan(args.addr as string) as T);
      case "vdb_rotate_key":
        return ok(mockRotateKey() as T);
      case "vdb_get_dag":
        return ok(mockGetDag() as T);
      case "vdb_get_merkle_tree":
        return ok(mockGetMerkleTree() as T);
      case "vdb_dev_corrupt_operation":
        return ok(mockDevCorruptOperation(
          (args.deviceId ?? args.device_id) as string,
          args.sequence as number
        ) as T);
      default:
        return err(`Unknown command: ${cmd}`) as ApiResult<T>;
    }
  } catch (e: any) {
    return err(e.message || String(e));
  }
}

export const api = {
  init: (path: string, passphrase: string) =>
    call<any>("vdb_init", { path, passphrase }),
  open: (path: string, passphrase: string) =>
    call<any>("vdb_open", { path, passphrase }),
  close: () => call<void>("vdb_close", {}),
  put: (key: string, value: string) =>
    call<any>("vdb_put", { key, value }),
  get: (key: string) => call<string>("vdb_get", { key }),
  status: () => call<any>("vdb_status", {}),
  verify: () => call<any>("vdb_verify", {}),
  queryAt: (clock: string) => call<any>("vdb_query_at", { clock }),
  log: () => call<any>("vdb_log", {}),
  listDevices: () => call<any>("vdb_list_devices", {}),
  trustDevice: (publicKey: string) =>
    call<any>("vdb_trust_device", { publicKey }),
  revokeDevice: (deviceId: string) =>
    call<any>("vdb_revoke_device", { deviceId }),
  backup: (output: string) => call<any>("vdb_backup", { output }),
  restore: (archive: string) => call<any>("vdb_restore", { archive }),
  snapshot: () => call<number>("vdb_snapshot", {}),
  syncLan: (addr: string) => call<any>("vdb_sync_lan", { addr }),
  rotateKey: () => call<any>("vdb_rotate_key", {}),
  getDag: () => call<any>("vdb_get_dag", {}),
  getMerkleTree: () => call<any>("vdb_get_merkle_tree", {}),
  devCorruptOperation: (deviceId: string, sequence: number) =>
    call<void>("vdb_dev_corrupt_operation", { deviceId, sequence }),
};
