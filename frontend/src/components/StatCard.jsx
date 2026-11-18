export default function StatCard({ label, value, hint, icon: Icon, tone = "blue" }) {
  const tones = {
    blue: "bg-blue-400/10 text-blue-200",
    cyan: "bg-cyan-400/10 text-cyan-200",
    red: "bg-rose-400/10 text-rose-200",
    amber: "bg-amber-400/10 text-amber-200",
    green: "bg-emerald-400/10 text-emerald-200",
  };

  return (
    <div className="panel p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow">{label}</p>
          <p className="mt-3 text-3xl font-semibold tracking-tight text-white">{value}</p>
          <p className="mt-1 text-xs text-slate-500">{hint}</p>
        </div>
        <div className={`rounded-xl p-3 ${tones[tone]}`}>
          <Icon size={20} />
        </div>
      </div>
    </div>
  );
}
