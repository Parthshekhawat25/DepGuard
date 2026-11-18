import {
  AlertTriangle,
  CheckCircle2,
  CircleHelp,
  ShieldAlert,
} from "lucide-react";

const styles = {
  vulnerable: {
    label: "Vulnerable",
    className: "border-rose-400/30 bg-rose-400/10 text-rose-200",
    icon: ShieldAlert,
  },
  no_known_match: {
    label: "No known match",
    className: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
    icon: CheckCircle2,
  },
  unresolved: {
    label: "Unresolved",
    className: "border-amber-400/30 bg-amber-400/10 text-amber-200",
    icon: CircleHelp,
  },
  scan_error: {
    label: "Scan error",
    className: "border-orange-400/30 bg-orange-400/10 text-orange-200",
    icon: AlertTriangle,
  },
};

export default function StatusBadge({ status }) {
  const config = styles[status] || styles.unresolved;
  const Icon = config.icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${config.className}`}
    >
      <Icon size={13} />
      {config.label}
    </span>
  );
}
