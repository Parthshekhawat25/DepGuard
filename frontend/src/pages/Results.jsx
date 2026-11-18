import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  Filter,
  Search,
} from "lucide-react";
import StatusBadge from "../components/StatusBadge";
import { reportUrl } from "../services/api";

function severityText(vulnerability) {
  return (vulnerability.severity || [])
    .map((item) => [item.type, item.score].filter(Boolean).join(": "))
    .filter(Boolean)
    .join(", ");
}

export default function Results({ scan }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [expanded, setExpanded] = useState({});

  const dependencies = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return (scan?.dependencies || []).filter((dependency) => {
      const matchesStatus = status === "all" || dependency.scan_status === status;
      const haystack = [
        dependency.package_name,
        dependency.installed_version,
        ...(dependency.vulnerability_ids || []),
      ].join(" ").toLowerCase();
      return matchesStatus && (!normalizedQuery || haystack.includes(normalizedQuery));
    });
  }, [query, scan, status]);

  if (!scan) {
    return (
      <div className="panel p-10 text-center">
        <p className="text-sm text-slate-400">Run a scan to see dependency results.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
        <div>
          <p className="eyebrow text-cyan-300/80">Scan results</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">{scan.filename}</h1>
          <p className="mt-2 text-xs text-slate-500">
            Scan ID {scan.scan_id} · {new Date(scan.scan_timestamp).toLocaleString()}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <a
            href={reportUrl(scan, "csv")}
            download
            className="inline-flex items-center gap-2 rounded-xl border border-slate-600 px-3 py-2 text-sm font-semibold text-slate-200 hover:border-cyan-300/60 hover:text-cyan-200"
          >
            <Download size={16} /> CSV
          </a>
          <a
            href={reportUrl(scan, "html")}
            download
            className="inline-flex items-center gap-2 rounded-xl border border-slate-600 px-3 py-2 text-sm font-semibold text-slate-200 hover:border-cyan-300/60 hover:text-cyan-200"
          >
            <Download size={16} /> HTML report
          </a>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {[
          ["Total", scan.summary.total, "text-white"],
          ["Vulnerable", scan.summary.vulnerable, "text-rose-300"],
          ["No match", scan.summary.no_known_match, "text-emerald-300"],
          ["Unresolved", scan.summary.unresolved, "text-amber-300"],
          ["Errors", scan.summary.scan_error, "text-orange-300"],
        ].map(([label, value, color]) => (
          <div key={label} className="panel p-4">
            <p className="text-xs text-slate-500">{label}</p>
            <p className={`mt-2 text-2xl font-semibold ${color}`}>{value}</p>
          </div>
        ))}
      </section>

      <section className="panel overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-slate-700/60 p-4 md:flex-row">
          <label className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={17} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search package or advisory ID"
              className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-2.5 pl-10 pr-3 text-sm text-slate-100 placeholder:text-slate-600"
            />
          </label>
          <label className="relative flex items-center">
            <Filter className="pointer-events-none absolute left-3 text-slate-500" size={16} />
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="rounded-xl border border-slate-700 bg-slate-900/70 py-2.5 pl-9 pr-8 text-sm text-slate-200"
            >
              <option value="all">All statuses</option>
              <option value="vulnerable">Vulnerable</option>
              <option value="no_known_match">No known match</option>
              <option value="unresolved">Unresolved</option>
              <option value="scan_error">Scan error</option>
            </select>
          </label>
        </div>

        <div className="divide-y divide-slate-800">
          {dependencies.length ? dependencies.map((dependency) => {
            const isExpanded = expanded[dependency.package_name];
            return (
              <div key={`${dependency.package_name}-${dependency.installed_version || "unresolved"}`}>
                <button
                  type="button"
                  onClick={() => setExpanded((current) => ({ ...current, [dependency.package_name]: !isExpanded }))}
                  className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 px-4 py-4 text-left transition hover:bg-slate-900/50 md:grid-cols-[auto_1.5fr_1fr_1fr_auto]"
                >
                  <span className="text-slate-500">
                    {isExpanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate font-semibold text-slate-100">{dependency.package_name}</span>
                    <span className="block truncate text-xs text-slate-500">
                      {dependency.installed_version || dependency.requested_version || "Version not resolved"}
                    </span>
                  </span>
                  <span className="hidden text-sm text-slate-400 md:block">
                    {dependency.vulnerabilities?.length || 0} finding(s)
                  </span>
                  <span className="hidden md:block"><StatusBadge status={dependency.scan_status} /></span>
                  <span className="md:hidden"><StatusBadge status={dependency.scan_status} /></span>
                  <span className="hidden text-xs text-slate-500 md:block">
                    {dependency.vulnerability_ids?.join(", ") || "—"}
                  </span>
                </button>

                {isExpanded && (
                  <div className="space-y-4 bg-slate-950/30 px-12 pb-5 pt-1">
                    {dependency.error && (
                      <div className="flex gap-2 rounded-lg border border-orange-400/20 bg-orange-400/5 p-3 text-sm text-orange-200">
                        <AlertTriangle size={17} className="shrink-0" />
                        {dependency.error}
                      </div>
                    )}
                    {dependency.vulnerabilities?.map((vulnerability, index) => (
                      <article key={`${vulnerability.vulnerability_id || "finding"}-${index}`} className="rounded-xl border border-rose-400/20 bg-rose-400/5 p-4">
                        <div className="flex flex-col justify-between gap-2 md:flex-row">
                          <div>
                            <p className="text-sm font-semibold text-rose-100">{vulnerability.vulnerability_id || "Advisory ID unavailable"}</p>
                            <p className="mt-1 text-sm text-slate-300">{vulnerability.summary || "Summary unavailable from source."}</p>
                          </div>
                          {severityText(vulnerability) && (
                            <span className="h-fit rounded-full bg-rose-400/10 px-2.5 py-1 text-xs font-semibold text-rose-200">
                              {severityText(vulnerability)}
                            </span>
                          )}
                        </div>
                        {vulnerability.details && <p className="mt-3 text-sm leading-6 text-slate-400">{vulnerability.details}</p>}
                        <div className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
                          <div>
                            <p className="font-semibold uppercase tracking-wider text-slate-600">Affected versions</p>
                            <p className="mt-1 text-slate-300">{vulnerability.affected_versions?.join(", ") || "Not explicitly provided"}</p>
                          </div>
                          <div>
                            <p className="font-semibold uppercase tracking-wider text-slate-600">Fixed versions</p>
                            <p className="mt-1 text-slate-300">{vulnerability.fixed_versions?.join(", ") || "Not explicitly provided"}</p>
                          </div>
                        </div>
                        {vulnerability.references?.length > 0 && (
                          <div className="mt-4 flex flex-wrap gap-3">
                            {vulnerability.references.map((reference, referenceIndex) => (
                              reference.url ? (
                                <a
                                  key={`${reference.url}-${referenceIndex}`}
                                  href={reference.url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="inline-flex items-center gap-1 text-xs font-semibold text-cyan-300 hover:text-cyan-200"
                                >
                                  {reference.type || "Reference"} <ExternalLink size={12} />
                                </a>
                              ) : null
                            ))}
                          </div>
                        )}
                      </article>
                    ))}
                    {dependency.scan_status === "no_known_match" && (
                      <p className="text-sm text-emerald-200/80">
                        OSV returned no matching advisory for this exact version. This is not a guarantee of safety.
                      </p>
                    )}
                    {dependency.scan_status === "unresolved" && (
                      <p className="text-sm text-amber-200/80">
                        DepGuard did not guess an installed version for this dependency.
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          }) : (
            <div className="p-10 text-center text-sm text-slate-500">No dependencies match the current filters.</div>
          )}
        </div>
      </section>

      {(scan.invalid_lines?.length > 0 || scan.unsupported_lines?.length > 0) && (
        <section className="panel p-5">
          <p className="eyebrow">Parser notes</p>
          <h2 className="mt-2 text-lg font-semibold text-white">Lines requiring attention</h2>
          <div className="mt-4 space-y-2">
            {[...(scan.invalid_lines || []), ...(scan.unsupported_lines || [])].map((issue, index) => (
              <div key={`${issue.line_number}-${index}`} className="rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-sm text-amber-100">
                <span className="font-semibold">Line {issue.line_number}:</span> {issue.reason}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
