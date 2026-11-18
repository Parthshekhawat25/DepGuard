import { useState } from "react";
import { AlertCircle, ShieldCheck } from "lucide-react";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import Results from "./pages/Results";
import { scanRequirements } from "./services/api";

export default function App() {
  const [view, setView] = useState("dashboard");
  const [scan, setScan] = useState(null);
  const [scanCount, setScanCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleScan(file) {
    setLoading(true);
    setError("");
    try {
      const result = await scanRequirements(file);
      setScan(result);
      setScanCount((current) => current + 1);
      setView("results");
    } catch (scanError) {
      setError(scanError.message);
    } finally {
      setLoading(false);
    }
  }

  function navigate(nextView) {
    setError("");
    setView(nextView);
  }

  return (
    <div className="min-h-screen bg-ink-950 text-slate-100 lg:flex">
      <Sidebar
        view={view}
        onNavigate={navigate}
        hasResults={Boolean(scan)}
      />
      <main className="min-w-0 flex-1">
        <header className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4 md:px-8">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <ShieldCheck size={15} className="text-cyan-300" />
            Local analysis workspace
          </div>
          <div className="rounded-full border border-emerald-400/20 bg-emerald-400/5 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-emerald-300">
            OSV connected by backend
          </div>
        </header>
        <div className="mx-auto max-w-[1500px] p-5 md:p-8">
          {error && view !== "new-scan" && (
            <div className="mb-5 flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
              <AlertCircle size={18} className="shrink-0" />
              {error}
            </div>
          )}
          {view === "dashboard" && (
            <Dashboard
              scan={scan}
              scanCount={scanCount}
              onNewScan={() => navigate("new-scan")}
              onViewResults={() => navigate("results")}
            />
          )}
          {view === "new-scan" && (
            <NewScan onScan={handleScan} loading={loading} error={error} />
          )}
          {view === "results" && <Results scan={scan} />}
        </div>
      </main>
    </div>
  );
}
