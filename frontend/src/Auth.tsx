import { useState } from "react";
import { api } from "./mockApi";
import type { AuthResponse, LoginCredentials, RegisterCredentials } from "./AuthTypes";

export default function Auth() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [credentials, setCredentials] = useState<LoginCredentials | RegisterCredentials>({
    username: "",
    password: "",
  });
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<AuthResponse | null>(null);

  async function handleSubmit() {
    setLoading(true);
    setResponse(null);

    const args = { 
      path: credentials.username + ".vdb", 
      passphrase: credentials.password 
    };

    const isLogin = mode === "login";

    try {
      const result = isLogin
        ? await api.open(args.path, args.passphrase)
        : await api.init(args.path, args.passphrase);

      if (result.success) {
        setResponse({
          success: true,
          user: {
            userId: result.data?.db_id || credentials.username,
            username: credentials.username,
            createdAt: Date.now(),
          },
        });
      } else {
        setResponse({
          success: false,
          error: {
            message: result.error?.message || "Authentication failed",
          },
        });
      }
    } catch (e: any) {
      setResponse({
        success: false,
        error: { message: e.message || "Authentication error" },
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 border border-gray-600 rounded-lg p-6 max-w-md w-full">
        <h2 className="text-2xl font-bold text-blue-400 text-center mb-6">
          {mode === "login" ? "Welcome Back" : "Create Account"}
        </h2>

        {response !== null && (
          <div className={`mb-4 p-3 rounded ${response.success ? "bg-green-500 text-white" : "bg-red-500 text-white"}`}>
            {response.success ? "Success!" : response.error?.message}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2 text-slate-300">
              Username
            </label>
            <input
              type="text"
              value={credentials.username}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setCredentials({ ...credentials, username: e.target.value })
              }
              placeholder="Enter username"
              required
              className="w-full bg-gray-700 border border-gray-500 rounded px-3 py-2 text-sm focus:ring-primary-500 focus:border-primary-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2 text-slate-300">
              Password
            </label>
            <input
              type="password"
              value={credentials.password}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setCredentials({ ...credentials, password: e.target.value })
              }
              placeholder="Enter password"
              required
              className="w-full bg-gray-700 border border-gray-500 rounded px-3 py-2 text-sm focus:ring-primary-500 focus:border-primary-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded bg-primary-600 hover:bg-primary-700 text-white font-medium py-2 px-4 transition-colors"
          >
            {loading ? "Processing..." : mode === "login" ? "Sign In" : "Create Account"}
          </button>
        </form>

        {response !== null && (
          <div className="mt-6 text-center text-slate-400 text-sm">
            {mode === "login" && (
              <p className="underline cursor-pointer" onClick={() => setMode("register")}>
                Create new account
              </p>
            )}
            {mode === "register" && (
              <p className="underline cursor-pointer" onClick={() => setMode("login")}>
                Already have an account? Sign in
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}