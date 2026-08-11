import { useState, useEffect } from "react";
import { api } from "./mockApi";
import type { DbStatus, DeviceInfo, OperationSummary } from "./types";

type Tab = "dashboard" | "devices" | "sync" | "time-travel" | "backup" | "keys";

interface IntegrityResult {
  status: string;
  verified: boolean;
}

function hex(bytes: Uint8Array | string): string {
  if (typeof bytes === "string") {
    return bytes;
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function App() {
  const [dbPath, setDbPath] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [operations, setOperations] = useState<OperationSummary[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [error, setError] = useState<string | null>(null);
  const [integrity, setIntegrity] = useState<IntegrityResult | null>(null);
  const [syncLog, setSyncLog] = useState<string[]>([]);
  const [syncing, setSyncing] = useState(false);

  // Key/value form state.
  const [keyInput, setKeyInput] = useState("");
  const [valueInput, setValueInput] = useState("");
  const [lookupKey, setLookupKey] = useState("");
  const [lookupValue, setLookupValue] = useState<string | null>(null);

  // Device trust form state.
  const [newPubkey, setNewPubkey] = useState("");

  // Time travel state.
  const [clockInput, setClockInput] = useState("");
  const [timeTravelEntries, setTimeTravelEntries] = useState<
    { key: string; value: string }[]
  >([]);

  // Backup state.
  const [backupPath, setBackupPath] = useState("");
  const [restorePath, setRestorePath] = useState("");

  async function initDb() {
    setError(null);
    if (!dbPath) {
      setError("Select a database path first");
      return;
    }
    try {
      const result = await api.init(dbPath, passphrase);
      if (result.success) {
        // Only load the full status here; do not set status from the
        // partial init response.
        await refreshStatus();
      } else {
        setError(result.error?.message || "Init failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function openDb() {
    setError(null);
    if (!dbPath) {
      setError("Select a database path first");
      return;
    }
    try {
      const result = await api.open(dbPath, passphrase);
      if (result.success) {
        // Only load the full status here; do not set status from the
        // partial open response.
        await refreshStatus();
      } else {
        setError(result.error?.message || "Open failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function closeDb() {
    try {
      await api.close();
      setStatus(null);
      setDevices([]);
      setOperations([]);
      setIntegrity(null);
      setDbPath(null);
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function refreshStatus() {
    try {
      const result = await api.status();
      if (result.success && result.data) {
        setStatus(result.data);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function refreshDevices() {
    try {
      const result = await api.listDevices();
      if (result.success && result.data) {
        setDevices(result.data.devices || []);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function refreshOperations() {
    try {
      const result = await api.log();
      if (result.success && result.data) {
        setOperations(result.data.operations || []);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function handlePut() {
    setError(null);
    try {
      const result = await api.put(keyInput, valueInput);
      if (result.success) {
        setKeyInput("");
        setValueInput("");
        refreshOperations();
        refreshStatus();
      } else {
        setError(result.error?.message || "Put failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleGet() {
    setError(null);
    setLookupValue(null);
    try {
      const result = await api.get(lookupKey);
      if (result.success && result.data !== undefined) {
        setLookupValue(result.data);
      } else {
        setError(result.error?.message || "Get failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleVerify() {
    setError(null);
    try {
      const result = await api.verify();
      if (result.success && result.data) {
        setIntegrity(result.data);
      } else {
        setError(result.error?.message || "Verify failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleTrust() {
    setError(null);
    try {
      const result = await api.trustDevice(newPubkey);
      if (result.success) {
        setNewPubkey("");
        refreshDevices();
        refreshStatus();
      } else {
        setError(result.error?.message || "Trust failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleRevoke(deviceId: string) {
    setError(null);
    try {
      const result = await api.revokeDevice(deviceId);
      if (result.success) {
        refreshDevices();
        refreshStatus();
      } else {
        setError(result.error?.message || "Revoke failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleBackup() {
    setError(null);
    if (!backupPath) {
      setError("Enter backup path");
      return;
    }
    try {
      const result = await api.backup(backupPath);
      if (result.success) {
        setBackupPath("");
        alert("Backup created successfully");
      } else {
        setError(result.error?.message || "Backup failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleRestore() {
    setError(null);
    if (!restorePath) {
      setError("Enter restore path");
      return;
    }
    try {
      const result = await api.restore(restorePath);
      if (result.success) {
        setRestorePath("");
        refreshStatus();
        refreshDevices();
        refreshOperations();
        alert("Restore completed");
      } else {
        setError(result.error?.message || "Restore failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleSnapshot() {
    setError(null);
    try {
      const result = await api.snapshot();
      if (result.success && result.data !== undefined) {
        alert(`Snapshot created: ${result.data}`);
        refreshStatus();
      } else {
        setError(result.error?.message || "Snapshot failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleSync() {
    setError(null);
    setSyncing(true);
    setSyncLog([]);
    try {
      const result = await api.syncLan("127.0.0.1:8443");
      if (result.success && result.data) {
        setSyncLog([
          `Sync completed: ${result.data.message}`,
          `Received: ${result.data.operations_received} ops`,
          `Sent: ${result.data.operations_sent} ops`,
          `Merged: ${result.data.operations_merged} ops`,
          `Merkle root: ${result.data.merkle_root}`,
        ]);
        refreshStatus();
      } else {
        setError(result.error?.message || "Sync failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setSyncing(false);
    }
  }

  async function handleTimeTravel() {
    setError(null);
    if (!clockInput) {
      setError("Enter a logical clock");
      return;
    }
    try {
      const result = await api.queryAt(clockInput);
      if (result.success && result.data) {
        setTimeTravelEntries(result.data.entries || []);
      } else {
        setError(result.error?.message || "Query failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  // When DB opens or tab changes, refresh data.
  useEffect(() => {
    if (status) {
      refreshDevices();
      refreshOperations();
    }
  }, [status]);

  // File picker for DB path.
  async function pickDbPath() {
    const selected = prompt("Enter database path:", dbPath || "veildb.vdb");
    if (selected) {
      setDbPath(selected);
    }
  }

  async function pickBackupPath() {
    const selected = prompt("Enter backup path:", "backup.vdb");
    if (selected) {
      setBackupPath(selected);
    }
  }

  async function pickRestorePath() {
    const selected = prompt("Enter restore path:", "backup.vdb");
    if (selected) {
      setRestorePath(selected);
    }
  }

  return (
    <div className="min-h-screen bg-dark-900 text-slate-200">
      <header className="bg-dark-800 border-b border-slate-700 px-6 py-4">
        <h1 className="text-2xl font-bold text-primary-400">VeilDB</h1>
        <p className="text-sm text-slate-400">
          Privacy-first, local-first, zero-trust database
        </p>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-dark-800 border-r border-slate-700 min-h-[calc(100vh-64px)] p-4">
          {!status ? (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">
                  Database Path
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={dbPath || ""}
                    onChange={(e) => setDbPath(e.target.value)}
                    placeholder="veildb.vdb"
                    className="flex-1 bg-dark-900 border border-slate-600 rounded px-2 py-1 text-sm"
                  />
                  <button
                    onClick={pickDbPath}
                    className="text-xs bg-dark-700 hover:bg-dark-600 px-2 py-1 rounded"
                  >
                    Browse
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">
                  Passphrase
                </label>
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter passphrase"
                  className="w-full bg-dark-900 border border-slate-600 rounded px-2 py-1 text-sm"
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={initDb}
                  className="flex-1 bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
                >
                  Init
                </button>
                <button
                  onClick={openDb}
                  className="flex-1 bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm"
                >
                  Open
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="mb-4 p-3 bg-dark-900 rounded border border-slate-700">
                <p className="text-xs text-slate-400 mb-1">Database</p>
                <p className="text-sm font-mono truncate">{dbPath}</p>
                <p className="text-xs text-slate-400 mt-2">Device</p>
                <p className="text-sm font-mono truncate">
                  {hex(status.self_device_id)}
                </p>
                <button
                  onClick={closeDb}
                  className="mt-3 w-full text-xs bg-red-900 hover:bg-red-800 text-red-200 rounded px-2 py-1"
                >
                  Close
                </button>
              </div>
              <div className="space-y-1">
                <TabButton
                  active={activeTab === "dashboard"}
                  onClick={() => setActiveTab("dashboard")}
                >
                  Dashboard
                </TabButton>
                <TabButton
                  active={activeTab === "keys"}
                  onClick={() => setActiveTab("keys")}
                >
                  Keys
                </TabButton>
                <TabButton
                  active={activeTab === "devices"}
                  onClick={() => setActiveTab("devices")}
                >
                  Devices
                </TabButton>
                <TabButton
                  active={activeTab === "sync"}
                  onClick={() => setActiveTab("sync")}
                >
                  Sync
                </TabButton>
                <TabButton
                  active={activeTab === "time-travel"}
                  onClick={() => setActiveTab("time-travel")}
                >
                  Time Travel
                </TabButton>
                <TabButton
                  active={activeTab === "backup"}
                  onClick={() => setActiveTab("backup")}
                >
                  Backup / Restore
                </TabButton>
              </div>
            </>
          )}
        </nav>

        {/* Main content */}
        <main className="flex-1 p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-900 border border-red-700 text-red-200 rounded">
              {error}
            </div>
          )}

          {!status ? (
            <div className="text-center text-slate-400 mt-20">
              <p className="text-lg">No database open</p>
              <p className="text-sm mt-2">
                Initialize a new database or open an existing one.
              </p>
            </div>
          ) : (
            <>
              {activeTab === "dashboard" && (
                <Dashboard
                  status={status}
                  integrity={integrity}
                  onVerify={handleVerify}
                  onSnapshot={handleSnapshot}
                  operations={operations}
                />
              )}
              {activeTab === "keys" && (
                <Keys
                  keyInput={keyInput}
                  valueInput={valueInput}
                  lookupKey={lookupKey}
                  lookupValue={lookupValue}
                  onKeyChange={setKeyInput}
                  onValueChange={setValueInput}
                  onLookupKeyChange={setLookupKey}
                  onPut={handlePut}
                  onGet={handleGet}
                />
              )}
              {activeTab === "devices" && (
                <Devices
                  devices={devices}
                  newPubkey={newPubkey}
                  onNewPubkeyChange={setNewPubkey}
                  onTrust={handleTrust}
                  onRevoke={handleRevoke}
                />
              )}
              {activeTab === "sync" && (
                <Sync
                  syncing={syncing}
                  syncLog={syncLog}
                  onSync={handleSync}
                />
              )}
              {activeTab === "time-travel" && (
                <TimeTravel
                  clockInput={clockInput}
                  entries={timeTravelEntries}
                  onClockChange={setClockInput}
                  onQuery={handleTimeTravel}
                />
              )}
              {activeTab === "backup" && (
                <Backup
                  backupPath={backupPath}
                  restorePath={restorePath}
                  onBackupPathChange={setBackupPath}
                  onRestorePathChange={setRestorePath}
                  onBackup={handleBackup}
                  onRestore={handleRestore}
                  onPickBackup={pickBackupPath}
                  onPickRestore={pickRestorePath}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-2 rounded text-sm ${
        active
          ? "bg-primary-700 text-white"
          : "text-slate-300 hover:bg-dark-700"
      }`}
    >
      {children}
    </button>
  );
}

function Dashboard({
  status,
  integrity,
  onVerify,
  onSnapshot,
  operations,
}: {
  status: DbStatus;
  integrity: IntegrityResult | null;
  onVerify: () => void;
  onSnapshot: () => void;
  operations: OperationSummary[];
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Dashboard</h2>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Operations</p>
          <p className="text-2xl font-bold">{status.operation_count}</p>
        </div>
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Devices</p>
          <p className="text-2xl font-bold">{status.device_count}</p>
        </div>
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Key Version</p>
          <p className="text-2xl font-bold">{status.key_version}</p>
        </div>
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Format Version</p>
          <p className="text-2xl font-bold">{status.format_version}</p>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Integrity</p>
        {integrity ? (
          <div>
            <span
              className={`inline-block px-2 py-1 rounded text-sm ${
                integrity.verified
                  ? "bg-green-900 text-green-200"
                  : "bg-red-900 text-red-200"
              }`}
            >
              {integrity.status}
            </span>
          </div>
        ) : (
          <button
            onClick={onVerify}
            className="bg-primary-600 hover:bg-primary-700 px-3 py-1 rounded text-sm"
          >
            Verify Integrity
          </button>
        )}
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Snapshot</p>
        <button
          onClick={onSnapshot}
          className="bg-dark-700 hover:bg-dark-600 px-3 py-1 rounded text-sm"
        >
          Create Snapshot
        </button>
        {status.latest_snapshot_id && (
          <p className="text-xs text-slate-400 mt-2">
            Latest: #{status.latest_snapshot_id}
          </p>
        )}
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Merkle Root</p>
        <p className="font-mono text-xs break-all">{hex(status.merkle_root)}</p>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Recent Operations</p>
        <div className="space-y-1 max-h-60 overflow-y-auto">
          {operations.length === 0 && (
            <p className="text-sm text-slate-500">No operations yet</p>
          )}
          {operations.map((op) => (
            <div
              key={`${op.device_id}-${op.sequence}`}
              className="text-xs flex justify-between"
            >
              <span className="font-mono">{op.sequence}</span>
              <span className="font-mono text-slate-400">
                {hex(op.device_id).slice(0, 16)}...
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Keys({
  keyInput,
  valueInput,
  lookupKey,
  lookupValue,
  onKeyChange,
  onValueChange,
  onLookupKeyChange,
  onPut,
  onGet,
}: {
  keyInput: string;
  valueInput: string;
  lookupKey: string;
  lookupValue: string | null;
  onKeyChange: (v: string) => void;
  onValueChange: (v: string) => void;
  onLookupKeyChange: (v: string) => void;
  onPut: () => void;
  onGet: () => void;
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Keys</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Put Key-Value</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={keyInput}
            onChange={(e) => onKeyChange(e.target.value)}
            placeholder="Key"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
          />
          <input
            type="text"
            value={valueInput}
            onChange={(e) => onValueChange(e.target.value)}
            placeholder="Value"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
          />
          <button
            onClick={onPut}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Store
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Get Value</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={lookupKey}
            onChange={(e) => onLookupKeyChange(e.target.value)}
            placeholder="Key"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
          />
          <button
            onClick={onGet}
            className="w-full bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm"
          >
            Retrieve
          </button>
          {lookupValue !== null && (
            <div className="mt-2 p-2 bg-dark-900 rounded border border-slate-600">
              <p className="text-sm font-mono break-all">{lookupValue}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Devices({
  devices,
  newPubkey,
  onNewPubkeyChange,
  onTrust,
  onRevoke,
}: {
  devices: DeviceInfo[];
  newPubkey: string;
  onNewPubkeyChange: (v: string) => void;
  onTrust: () => void;
  onRevoke: (id: string) => void;
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Devices</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Trust New Device</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={newPubkey}
            onChange={(e) => onNewPubkeyChange(e.target.value)}
            placeholder="Public key (64 hex chars)"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={onTrust}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Trust Device
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Trusted Devices</h3>
        <div className="space-y-2">
          {devices.map((d) => (
            <div
              key={d.device_id}
              className="flex items-center justify-between bg-dark-900 rounded border border-slate-700 p-2"
            >
              <div>
                <p className="text-sm font-mono">{hex(d.device_id)}</p>
                <p className="text-xs text-slate-400">
                  {d.trusted ? "Trusted" : "Revoked"}
                </p>
              </div>
              {d.trusted && (
                <button
                  onClick={() => onRevoke(d.device_id)}
                  className="text-xs bg-red-900 hover:bg-red-800 text-red-200 px-2 py-1 rounded"
                >
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Sync({
  syncing,
  syncLog,
  onSync,
}: {
  syncing: boolean;
  syncLog: string[];
  onSync: () => void;
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Sync</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">LAN Sync</h3>
        <button
          onClick={onSync}
          disabled={syncing}
          className="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-slate-600 text-white rounded px-3 py-2 text-sm"
        >
          {syncing ? "Syncing..." : "Sync with LAN peer"}
        </button>
      </div>

      {syncLog.length > 0 && (
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">Sync Log</h3>
          <div className="space-y-1">
            {syncLog.map((line, i) => (
              <p key={i} className="text-sm font-mono">
                {line}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function TimeTravel({
  clockInput,
  entries,
  onClockChange,
  onQuery,
}: {
  clockInput: string;
  entries: { key: string; value: string }[];
  onClockChange: (v: string) => void;
  onQuery: () => void;
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Time Travel</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">
          Query at Logical Clock
        </h3>
        <div className="space-y-2">
          <input
            type="text"
            value={clockInput}
            onChange={(e) => onClockChange(e.target.value)}
            placeholder='e.g. "device_id:counter"'
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={onQuery}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Query
          </button>
        </div>
      </div>

      {entries.length > 0 && (
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">State at Clock</h3>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {entries.map((e, i) => (
              <div
                key={i}
                className="flex justify-between bg-dark-900 rounded border border-slate-700 p-2"
              >
                <span className="text-sm">{e.key}</span>
                <span className="text-sm text-slate-400">{e.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Backup({
  backupPath,
  restorePath,
  onBackupPathChange,
  onRestorePathChange,
  onBackup,
  onRestore,
  onPickBackup,
  onPickRestore,
}: {
  backupPath: string;
  restorePath: string;
  onBackupPathChange: (v: string) => void;
  onRestorePathChange: (v: string) => void;
  onBackup: () => void;
  onRestore: () => void;
  onPickBackup: () => void;
  onPickRestore: () => void;
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Backup / Restore</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Backup</h3>
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={backupPath}
              onChange={(e) => onBackupPathChange(e.target.value)}
              placeholder="backup.vdb"
              className="flex-1 bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <button
              onClick={onPickBackup}
              className="text-sm bg-dark-700 hover:bg-dark-600 px-3 py-2 rounded"
            >
              Browse
            </button>
          </div>
          <button
            onClick={onBackup}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Create Backup
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Restore</h3>
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={restorePath}
              onChange={(e) => onRestorePathChange(e.target.value)}
              placeholder="backup.vdb"
              className="flex-1 bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <button
              onClick={onPickRestore}
              className="text-sm bg-dark-700 hover:bg-dark-600 px-3 py-2 rounded"
            >
              Browse
            </button>
          </div>
          <button
            onClick={onRestore}
            className="w-full bg-red-900 hover:bg-red-800 text-red-200 rounded px-3 py-2 text-sm"
          >
            Restore (overwrites current DB)
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;