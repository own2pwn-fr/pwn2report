import { Badge } from "@/components/ui/badge";

// CVSS v3.x metric decoder. Covers the base-metric group only (the part this
// read-only UI surfaces). Temporal / environmental metrics are ignored.
// Ported from secai dashboard's cvss-vector component.
const METRICS: Record<string, { label: string; values: Record<string, string> }> = {
  AV: { label: "Attack vector", values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { label: "Attack complexity", values: { L: "Low", H: "High" } },
  PR: { label: "Privileges required", values: { N: "None", L: "Low", H: "High" } },
  UI: { label: "User interaction", values: { N: "None", R: "Required" } },
  S: { label: "Scope", values: { U: "Unchanged", C: "Changed" } },
  C: { label: "Confidentiality", values: { N: "None", L: "Low", H: "High" } },
  I: { label: "Integrity", values: { N: "None", L: "Low", H: "High" } },
  A: { label: "Availability", values: { N: "None", L: "Low", H: "High" } },
};

export function CvssVector({
  vector,
  score,
}: {
  vector: string;
  score?: number | null;
}) {
  const parts = parseVector(vector);
  if (parts.length === 0) {
    return (
      <div className="break-all font-mono text-xs text-muted-foreground">{vector}</div>
    );
  }
  return (
    <div className="space-y-2">
      {score != null && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Badge variant="secondary" className="font-mono">
            Score {score.toFixed(1)}
          </Badge>
          <span className="break-all font-mono text-muted-foreground">{vector}</span>
        </div>
      )}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs md:grid-cols-4">
        {parts.map(({ code, value, label, decoded }) => (
          <div key={code} className="space-y-0.5">
            <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">
              {label}
            </dt>
            <dd>
              <span className="font-mono">
                {code}:{value}
              </span>
              <span className="ml-1 text-muted-foreground">{decoded}</span>
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function parseVector(vector: string) {
  const out: { code: string; value: string; label: string; decoded: string }[] = [];
  for (const segment of vector.split("/")) {
    const [code, value] = segment.split(":");
    if (!code || !value) continue;
    const def = METRICS[code];
    if (!def) continue;
    out.push({ code, value, label: def.label, decoded: def.values[value] ?? value });
  }
  return out;
}
