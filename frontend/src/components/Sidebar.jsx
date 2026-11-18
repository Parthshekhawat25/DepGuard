import {
  FileSearch,
  LayoutDashboard,
  ListChecks,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";

const navigation = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "new-scan", label: "New scan", icon: UploadCloud },
  { id: "results", label: "Results", icon: ListChecks },
];

export default function Sidebar({ view, onNavigate, hasResults }) {
  return (
    <aside className="flex w-full shrink-0 flex-col border-b border-slate-800 bg-ink-950/80 px-5 py-5 lg:min-h-screen lg:w-64 lg:border-b-0 lg:border-r lg:px-4">
      <div className="flex items-center gap-3 px-2">
        <div className="rounded-xl bg-cyan-300/10 p-2 text-signal-cyan">
          <ShieldCheck size={23} />
        </div>
        <div>
          <p className="font-semibold tracking-tight text-white">DepGuard</p>
          <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Risk analyzer</p>
        </div>
      </div>

      <nav className="mt-8 flex gap-2 overflow-x-auto lg:flex-col">
        {navigation.map(({ id, label, icon: Icon }) => {
          const disabled = id === "results" && !hasResults;
          const active = view === id;
          return (
            <button
              key={id}
              type="button"
              disabled={disabled}
              onClick={() => onNavigate(id)}
              className={`flex min-w-max items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm transition ${
                active
                  ? "bg-blue-500/15 font-semibold text-blue-200"
                  : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-100"
              } ${disabled ? "cursor-not-allowed opacity-40" : ""}`}
            >
              <Icon size={17} />
              {label}
            </button>
          );
        })}
      </nav>

      <div className="mt-auto hidden rounded-xl border border-slate-800 bg-slate-900/50 p-4 lg:block">
        <FileSearch className="text-signal-cyan" size={18} />
        <p className="mt-3 text-xs font-semibold text-slate-200">Evidence-first scanning</p>
        <p className="mt-1 text-xs leading-5 text-slate-500">
          No match is not a guarantee of safety. Every result keeps its source context.
        </p>
      </div>
    </aside>
  );
}
