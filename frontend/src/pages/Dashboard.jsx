import {
  Activity,
  Bug,
  FileCheck2,
  PackageCheck,
  ScanLine,
} from "lucide-react";
import StatCard from "../components/StatCard";

const emptySummary = {
  total: 0,
  vulnerable: 0,
  no_known_match: 0,
  unresolved: 0,
  scan_error: 0,
  total_unique_vulnerability_ids: 0,
};

function severityRows(scan) {
  const counts = {};
  for (const dependency of scan?.dependencies || []) {
    for (const vulnerability of dependency.vulnerabilities || []) {
      for (const severity of vulnerability.severity || []) {
        const key = severity.type || "Unspecified";
        counts[key] = (counts[key] || 0) + 1;
      }
    }
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}

export default function Dashboard({ scan, scanCount, onNewScan, onViewResults }) {
  const summary = scan?.summary || emptySummary;
  const severity = severityRows(scan);

  return (
    <div className="space-y-7">
      <section className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="eyebrow text-cyan-300/80">Security workspace</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white md:text-4xl">
            Dependency risk, made understandable.
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
            Analyze pinned Python dependencies against OSV and keep uncertainty visible.
          </p>
        </div>
        <button
          type="button"
          onClick={onNewScan}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-500 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-blue-500/20 transition hover:bg-blue-400"
        >
          <ScanLine size={17} />
          Start a scan
        </button>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total scans" value={scanCount} hint="This session" icon={Activity} tone="cyan" />
        <StatCard label="Dependencies analyzed" value={summary.total} hint="From latest scan" icon={PackageCheck} />
        <StatCard label="Vulnerabilities detected" value={summary.total_unique_vulnerability_ids} hint="Unique advisory IDs" icon={Bug} tone="red" />
        <StatCard label="No known match" value={summary.no_known_match} hint="Not a security guarantee" icon={FileCheck2} tone="green" />
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="panel p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="eyebrow">Latest scan</p>
              <h2 className="mt-2 text-lg font-semibold text-white">
                {scan?.filename || "No scan has been run yet"}
              </h2>
            </div>
            {scan && (
              <button
                type="button"
                onClick={onViewResults}
                className="text-sm font-semibold text-cyan-300 hover:text-cyan-200"
              >
                View results
              </button>
            )}
          </div>
          {scan ? (
            <div className="mt-6 grid gap-3 sm:grid-cols-4">
              {[
                ["Vulnerable", summary.vulnerable, "text-rose-300"],
                ["Unresolved", summary.unresolved, "text-amber-300"],
                ["Scan errors", summary.scan_error, "text-orange-300"],
                ["Advisory IDs", summary.total_unique_vulnerability_ids, "text-cyan-300"],
              ].map(([label, value, color]) => (
                <div key={label} className="rounded-xl border border-slate-700/60 bg-slate-900/40 p-4">
                  <p className="text-xs text-slate-500">{label}</p>
                  <p className={`mt-2 text-2xl font-semibold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-6 rounded-xl border border-dashed border-slate-700 p-8 text-center">
              <ScanLine className="mx-auto text-slate-500" size={28} />
              <p className="mt-3 text-sm text-slate-300">Upload a requirements.txt file to begin.</p>
            </div>
          )}
        </div>

        <div className="panel p-5">
          <p className="eyebrow">Severity overview</p>
          <h2 className="mt-2 text-lg font-semibold text-white">Source-provided severity</h2>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            Severity is shown only when OSV supplies it. Missing severity is not inferred.
          </p>
          <div className="mt-5 space-y-3">
            {severity.length ? severity.map(([label, count]) => (
              <div key={label} className="flex items-center justify-between rounded-lg bg-slate-900/50 px-3 py-2.5">
                <span className="text-sm text-slate-300">{label}</span>
                <span className="rounded-full bg-rose-400/10 px-2 py-0.5 text-xs font-semibold text-rose-200">{count}</span>
              </div>
            )) : (
              <div className="rounded-xl border border-dashed border-slate-700 p-5 text-sm text-slate-500">
                No severity data is available yet.
              </div>
            )}
          </div>
        </div>
      </section>

      {scan && (
        <p className="text-xs text-slate-600">
          Last scan completed {new Date(scan.scan_timestamp).toLocaleString()}.
        </p>
      )}
    </div>
  );
}
