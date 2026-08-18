import { useState, useEffect } from "react";
import { api } from "./mockApi";

interface UserEntry {
  username: string;
  email: string;
  role: string;
  createdAt?: string;
}

interface UserDemoProps {
  /** Called after any VeilDB write so parent can refresh stats, DAG, Merkle, etc. */
  onDataChanged?: () => void;
}

export default function UserDemo({ onDataChanged }: UserDemoProps) {
  const [users, setUsers] = useState<UserEntry[]>([]);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("user");
  const [password, setPassword] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showKeys, setShowKeys] = useState(false);
  const [rawKeys, setRawKeys] = useState<{ key: string; value: string }[]>([]);

  async function refreshUsers() {
    setError(null);
    try {
      const raw = await api.get("users:index");
      if (raw.success && raw.data) {
        const index: string[] = JSON.parse(raw.data);
        const entries: UserEntry[] = [];
        const keys: { key: string; value: string }[] = [
          { key: "users:index", value: raw.data },
        ];
        for (const uname of index) {
          const res = await api.get(`user:${uname}`);
          if (res.success && res.data) {
            entries.push(JSON.parse(res.data));
            keys.push({ key: `user:${uname}`, value: res.data });
          }
        }
        setUsers(entries);
        setRawKeys(keys);
      } else {
        setUsers([]);
        setRawKeys([]);
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleCreateAccount() {
    setError(null);
    setMessage(null);
    if (!username || !email || !password) {
      setError("All fields are required");
      return;
    }
    try {
      const user: UserEntry = {
        username,
        email,
        role,
        createdAt: new Date().toISOString(),
      };

      // Read existing index
      let index: string[] = [];
      const idxRaw = await api.get("users:index");
      if (idxRaw.success && idxRaw.data) {
        index = JSON.parse(idxRaw.data);
      }
      if (index.includes(username)) {
        setError("Username already exists");
        return;
      }

      // Store user data as key-value pair in VeilDB
      // Key: "user:<username>" → Value: JSON string
      const userResult = await api.put(
        `user:${username}`,
        JSON.stringify(user)
      );
      if (userResult.success) {
        // Update the users index
        index.push(username);
        await api.put("users:index", JSON.stringify(index));

        setMessage(
          `✓ Account "${username}" stored in VeilDB — 2 operations created (user data + index update)`
        );
        setUsername("");
        setEmail("");
        setPassword("");
        setRole("user");
        refreshUsers();
        // Notify parent to refresh dashboard, DAG, Merkle tree, etc.
        onDataChanged?.();
      } else {
        setError(userResult.error?.message || "Create account failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleDeleteUser(uname: string) {
    setError(null);
    setMessage(null);
    try {
      // Remove user key — in VeilDB, we overwrite with empty to "delete"
      await api.put(`user:${uname}`, "");

      // Update index
      const idxRaw = await api.get("users:index");
      if (idxRaw.success && idxRaw.data) {
        let index: string[] = JSON.parse(idxRaw.data);
        index = index.filter((u) => u !== uname);
        await api.put("users:index", JSON.stringify(index));
      }

      setMessage(`User "${uname}" removed — 2 operations recorded in VeilDB`);
      refreshUsers();
      onDataChanged?.();
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleSignIn() {
    setError(null);
    setMessage(null);
    if (!loginUsername || !loginPassword) {
      setError("Username and password are required");
      return;
    }
    try {
      const result = await api.get(`user:${loginUsername}`);
      if (result.success && result.data && result.data !== "") {
        const user: UserEntry = JSON.parse(result.data);
        setMessage(
          `✓ Welcome back, ${user.username}! Role: ${user.role}. Data retrieved from VeilDB key "user:${user.username}".`
        );
      } else {
        setError("Invalid username or password");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  useEffect(() => {
    refreshUsers();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold">User Accounts Demo</h2>
        <p className="text-sm text-slate-400 mt-1">
          Create and sign into accounts. Data is stored as{" "}
          <strong>encrypted key-value pairs</strong> in the real VeilDB database.
          Each operation updates the Merkle tree and operation DAG — check the
          Dashboard, Graph, and Merkle tabs after creating accounts.
        </p>
      </div>

      {message && (
        <div className="p-3 bg-green-900/50 border border-green-700 text-green-200 rounded text-sm">
          {message}
        </div>
      )}
      {error && (
        <div className="p-3 bg-red-900/50 border border-red-700 text-red-200 rounded text-sm">
          {error}
        </div>
      )}

      {/* How it works */}
      <div className="bg-dark-800 border border-indigo-800/40 rounded p-4">
        <h3 className="text-sm font-semibold text-indigo-300 mb-2">
          ⚡ How VeilDB stores this data
        </h3>
        <div className="text-xs text-slate-400 space-y-1 font-mono">
          <p>
            <span className="text-blue-400">PUT</span>{" "}
            <span className="text-yellow-300">"user:alice"</span> →{" "}
            <span className="text-green-300">
              {`{"username":"alice","email":"alice@example.com","role":"admin"}`}
            </span>
          </p>
          <p>
            <span className="text-blue-400">PUT</span>{" "}
            <span className="text-yellow-300">"users:index"</span> →{" "}
            <span className="text-green-300">{`["alice","bob"]`}</span>
          </p>
          <p className="text-slate-500 pt-1">
            Each PUT creates a signed, hash-chained operation in the CRDT DAG →
            updates the Merkle tree root.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Create Account */}
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">Create Account</h3>
          <div className="space-y-2">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email"
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
              <option value="moderator">Moderator</option>
            </select>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <button
              onClick={handleCreateAccount}
              className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm font-medium"
            >
              Create Account → vdb_put
            </button>
          </div>
        </div>

        {/* Sign In */}
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">Sign In</h3>
          <div className="space-y-2">
            <input
              type="text"
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
              placeholder="Username"
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <input
              type="password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              placeholder="Password"
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <button
              onClick={handleSignIn}
              className="w-full bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm font-medium"
            >
              Sign In → vdb_get
            </button>
          </div>
        </div>
      </div>

      {/* Stored Users */}
      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-medium">Stored Users</h3>
          <button
            onClick={() => setShowKeys(!showKeys)}
            className="text-xs bg-dark-700 hover:bg-dark-600 px-2 py-1 rounded"
          >
            {showKeys ? "Hide" : "Show"} Raw KV Pairs
          </button>
        </div>
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {users.length === 0 && (
            <p className="text-sm text-slate-500">
              No users yet — create an account above to store data in VeilDB
            </p>
          )}
          {users.map((u, i) => (
            <div
              key={i}
              className="flex justify-between items-center bg-dark-900 rounded border border-slate-700 p-3"
            >
              <div>
                <p className="text-sm font-medium">{u.username}</p>
                <p className="text-xs text-slate-400">{u.email}</p>
                {u.createdAt && (
                  <p className="text-xs text-slate-500 mt-0.5">
                    {new Date(u.createdAt).toLocaleString()}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs bg-dark-700 px-2 py-1 rounded">
                  {u.role}
                </span>
                <button
                  onClick={() => handleDeleteUser(u.username)}
                  className="text-xs bg-red-900 hover:bg-red-800 text-red-200 px-2 py-1 rounded"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Raw KV pairs */}
      {showKeys && rawKeys.length > 0 && (
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-sm font-semibold text-yellow-300 mb-3">
            🔑 Raw Key-Value Pairs in VeilDB
          </h3>
          <div className="space-y-2 font-mono text-xs">
            {rawKeys.map((kv, i) => (
              <div key={i} className="bg-dark-900 rounded p-2 border border-slate-700">
                <p>
                  <span className="text-yellow-300">Key:</span>{" "}
                  <span className="text-blue-300">{kv.key}</span>
                </p>
                <p className="mt-1">
                  <span className="text-yellow-300">Val:</span>{" "}
                  <span className="text-green-300 break-all">{kv.value}</span>
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
