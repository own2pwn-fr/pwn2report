import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";

// CVSS v3.x metric decoder. Covers the base-metric group only (the part this
// read-only UI surfaces). Temporal / environmental metrics are ignored.
// Ported from secai dashboard's cvss-vector component. Labels resolve through
// i18n under the shared `cvss.metrics.*` namespace.
const METRICS: Record<string, { values: Record<string, string> }> = {
  AV: { values: { N: "network", A: "adjacent", L: "local", P: "physical" } },
  AC: { values: { L: "low", H: "high" } },
  PR: { values: { N: "none", L: "low", H: "high" } },
  UI: { values: { N: "none", R: "required" } },
  S: { values: { U: "unchanged", C: "changed" } },
  C: { values: { N: "none", L: "low", H: "high" } },
  I: { values: { N: "none", L: "low", H: "high" } },
  A: { values: { N: "none", L: "low", H: "high" } },
};

export function CvssVector({
  vector,
  score,
}: {
  vector: string;
  score?: number | null;
}) {
  const { t } = useTranslation();
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
            {t("cvss.score", { score: score.toFixed(1) })}
          </Badge>
          <span className="break-all font-mono text-muted-foreground">{vector}</span>
        </div>
      )}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs md:grid-cols-4">
        {parts.map(({ code, value, valueKey }) => (
          <div key={code} className="space-y-0.5">
            <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">
              {t(`cvss.metrics.${code}`)}
            </dt>
            <dd>
              <span className="font-mono">
                {code}:{value}
              </span>
              <span className="ml-1 text-muted-foreground">
                {valueKey ? t(`cvss.metrics.values.${valueKey}`) : value}
              </span>
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function parseVector(vector: string) {
  const out: { code: string; value: string; valueKey: string | null }[] = [];
  for (const segment of vector.split("/")) {
    const [code, value] = segment.split(":");
    if (!code || !value) continue;
    const def = METRICS[code];
    if (!def) continue;
    out.push({ code, value, valueKey: def.values[value] ?? null });
  }
  return out;
}
