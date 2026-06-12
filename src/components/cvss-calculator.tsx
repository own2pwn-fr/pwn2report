import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { CVSS31, CVSS40 } from "@pandatix/js-cvss";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// CVSS version handled by the calculator.
type CvssVersion = "3.1" | "4.0";

// A base-metric definition: its key, a label, and the ordered list of allowed
// values (value code + human label). The first value is the default.
interface MetricDef {
  key: string;
  label: string;
  values: { code: string; label: string }[];
}

// CVSS 3.1 base metric group (https://www.first.org/cvss/v3.1/specification-document).
const METRICS_31: MetricDef[] = [
  {
    key: "AV",
    label: "Attack Vector",
    values: [
      { code: "N", label: "Network" },
      { code: "A", label: "Adjacent" },
      { code: "L", label: "Local" },
      { code: "P", label: "Physical" },
    ],
  },
  {
    key: "AC",
    label: "Attack Complexity",
    values: [
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "PR",
    label: "Privileges Required",
    values: [
      { code: "N", label: "None" },
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "UI",
    label: "User Interaction",
    values: [
      { code: "N", label: "None" },
      { code: "R", label: "Required" },
    ],
  },
  {
    key: "S",
    label: "Scope",
    values: [
      { code: "U", label: "Unchanged" },
      { code: "C", label: "Changed" },
    ],
  },
  {
    key: "C",
    label: "Confidentiality",
    values: [
      { code: "N", label: "None" },
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "I",
    label: "Integrity",
    values: [
      { code: "N", label: "None" },
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "A",
    label: "Availability",
    values: [
      { code: "N", label: "None" },
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
];

// CVSS 4.0 base metric group (https://www.first.org/cvss/v4.0/specification-document).
const METRICS_40: MetricDef[] = [
  {
    key: "AV",
    label: "Attack Vector",
    values: [
      { code: "N", label: "Network" },
      { code: "A", label: "Adjacent" },
      { code: "L", label: "Local" },
      { code: "P", label: "Physical" },
    ],
  },
  {
    key: "AC",
    label: "Attack Complexity",
    values: [
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "AT",
    label: "Attack Requirements",
    values: [
      { code: "N", label: "None" },
      { code: "P", label: "Present" },
    ],
  },
  {
    key: "PR",
    label: "Privileges Required",
    values: [
      { code: "N", label: "None" },
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "UI",
    label: "User Interaction",
    values: [
      { code: "N", label: "None" },
      { code: "P", label: "Passive" },
      { code: "A", label: "Active" },
    ],
  },
  {
    key: "VC",
    label: "Confidentiality (VC)",
    values: [
      { code: "H", label: "High" },
      { code: "L", label: "Low" },
      { code: "N", label: "None" },
    ],
  },
  {
    key: "VI",
    label: "Integrity (VI)",
    values: [
      { code: "H", label: "High" },
      { code: "L", label: "Low" },
      { code: "N", label: "None" },
    ],
  },
  {
    key: "VA",
    label: "Availability (VA)",
    values: [
      { code: "H", label: "High" },
      { code: "L", label: "Low" },
      { code: "N", label: "None" },
    ],
  },
  {
    key: "SC",
    label: "Subsequent Confidentiality (SC)",
    values: [
      { code: "H", label: "High" },
      { code: "L", label: "Low" },
      { code: "N", label: "None" },
    ],
  },
  {
    key: "SI",
    label: "Subsequent Integrity (SI)",
    values: [
      { code: "H", label: "High" },
      { code: "L", label: "Low" },
      { code: "N", label: "None" },
    ],
  },
  {
    key: "SA",
    label: "Subsequent Availability (SA)",
    values: [
      { code: "H", label: "High" },
      { code: "L", label: "Low" },
      { code: "N", label: "None" },
    ],
  },
];

const PREFIX: Record<CvssVersion, string> = { "3.1": "CVSS:3.1", "4.0": "CVSS:4.0" };

function metricsFor(version: CvssVersion): MetricDef[] {
  return version === "3.1" ? METRICS_31 : METRICS_40;
}

function defaultSelections(version: CvssVersion): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of metricsFor(version)) out[m.key] = m.values[0].code;
  return out;
}

/** Detect the version from a CVSS vector string prefix. */
function versionOf(vector: string): CvssVersion | null {
  if (vector.startsWith("CVSS:4.0")) return "4.0";
  if (vector.startsWith("CVSS:3.1")) return "3.1";
  return null;
}

/** Parse a vector into per-metric selections for the given version. */
function selectionsFromVector(version: CvssVersion, vector: string): Record<string, string> {
  const out = defaultSelections(version);
  const defs = metricsFor(version);
  for (const seg of vector.split("/")) {
    const [key, value] = seg.split(":");
    const def = defs.find((d) => d.key === key);
    if (def && def.values.some((v) => v.code === value)) out[key] = value;
  }
  return out;
}

/** Build the vector string from selections (base metrics only). */
function buildVector(version: CvssVersion, sel: Record<string, string>): string {
  const segs = metricsFor(version).map((m) => `${m.key}:${sel[m.key]}`);
  return `${PREFIX[version]}/${segs.join("/")}`;
}

/** Compute base score + severity for a complete base vector. */
function compute(version: CvssVersion, vector: string): { score: number; severity: string } {
  if (version === "3.1") {
    const c = new CVSS31(vector);
    const score = c.BaseScore();
    return { score, severity: CVSS31.Rating(score) };
  }
  const c = new CVSS40(vector);
  const score = c.Score();
  return { score, severity: CVSS40.Rating(score) };
}

const RATING_CLASS: Record<string, string> = {
  CRITICAL: "bg-[hsl(var(--sev-critical)/0.18)] text-[hsl(var(--sev-critical))]",
  HIGH: "bg-[hsl(var(--sev-high)/0.18)] text-[hsl(var(--sev-high))]",
  MEDIUM: "bg-[hsl(var(--sev-medium)/0.18)] text-[hsl(var(--sev-medium))]",
  LOW: "bg-[hsl(var(--sev-low)/0.18)] text-[hsl(var(--sev-low))]",
  NONE: "bg-muted text-muted-foreground",
};

/**
 * Interactive CVSS 3.1 / 4.0 base-score calculator. Emits the computed
 * `{ vector, score }` upward whenever a metric or the version changes.
 */
export function CvssCalculator({
  vector,
  onChange,
}: {
  vector: string | null;
  onChange: (next: { vector: string; score: number }) => void;
}) {
  const { t } = useTranslation();

  const initialVersion = (vector && versionOf(vector)) || "3.1";
  const [version, setVersion] = useState<CvssVersion>(initialVersion);
  const [selections, setSelections] = useState<Record<string, string>>(() =>
    vector && versionOf(vector)
      ? selectionsFromVector(initialVersion, vector)
      : defaultSelections(initialVersion),
  );

  const result = useMemo(() => {
    const v = buildVector(version, selections);
    try {
      const { score, severity } = compute(version, v);
      return { vector: v, score, severity };
    } catch {
      return { vector: v, score: 0, severity: "NONE" };
    }
  }, [version, selections]);

  // Emit upward on every recompute. Guard the very first run so we don't clobber
  // an existing finding's stored vector before the user touches anything.
  const seeded = useRef(false);
  useEffect(() => {
    if (!seeded.current) {
      seeded.current = true;
      return;
    }
    onChange({ vector: result.vector, score: result.score });
    // onChange identity is owned by the parent; recompute only on result change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result.vector, result.score]);

  const switchVersion = (next: CvssVersion) => {
    if (next === version) return;
    setVersion(next);
    setSelections(defaultSelections(next));
    seeded.current = true; // a deliberate version switch SHOULD emit.
  };

  const setMetric = (key: string, code: string) =>
    setSelections((prev) => ({ ...prev, [key]: code }));

  return (
    <div className="space-y-4 rounded-md border bg-muted/20 p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="inline-flex rounded-md border p-0.5">
          {(["3.1", "4.0"] as CvssVersion[]).map((v) => (
            <button
              key={v}
              type="button"
              onClick={() => switchVersion(v)}
              className={cn(
                "rounded px-3 py-1 text-xs font-medium transition-colors",
                version === v
                  ? "bg-[hsl(var(--accent-brand))] text-white"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {t("cvss.version", { version: v })}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="font-mono">
            {t("cvss.score", { score: result.score.toFixed(1) })}
          </Badge>
          <Badge className={cn("font-medium", RATING_CLASS[result.severity])}>
            {t(`cvss.rating.${result.severity}`)}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-3 md:grid-cols-3">
        {metricsFor(version).map((m) => (
          <div key={m.key} className="space-y-1">
            <Label className="text-[11px] text-muted-foreground">
              {m.label} <span className="font-mono">({m.key})</span>
            </Label>
            <div className="flex flex-wrap gap-1">
              {m.values.map((val) => (
                <Button
                  key={val.code}
                  type="button"
                  size="sm"
                  variant={selections[m.key] === val.code ? "brand" : "outline"}
                  className="h-7 px-2 text-xs"
                  onClick={() => setMetric(m.key, val.code)}
                  title={val.label}
                >
                  {val.code}
                </Button>
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="break-all font-mono text-[11px] text-muted-foreground">{result.vector}</p>
    </div>
  );
}
