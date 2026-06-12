import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Plus, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { CvssCalculator } from "@/components/cvss-calculator";
import type {
  Confidence,
  Evidence,
  Finding,
  FindingKind,
  FindingPatch,
  NewFinding,
  Severity,
  StructuredPoc,
  TriageStatus,
} from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES: Confidence[] = ["high", "medium", "low"];
const KINDS: FindingKind[] = ["manual", "sast", "iac", "sca", "secret"];
const TRIAGE: TriageStatus[] = ["open", "acknowledged", "false_positive", "resolved"];

export interface FindingFormState {
  title: string;
  severity: Severity;
  confidence: Confidence;
  kind: FindingKind;
  cwe: string;
  cve: string;
  cvss_vector: string;
  cvss_score: number | null;
  triage_status: TriageStatus;
  triage_note: string;
  // description facets
  summary: string;
  root_cause: string;
  attack_vector: string;
  business_impact: string;
  technical_details: string;
  // remediation
  fix: string;
  code_patch: string;
  references: string[];
  // evidence
  ev_file: string;
  ev_start_line: string;
  ev_end_line: string;
  ev_snippet: string;
  // poc
  poc_scenario: string;
  poc_steps: string[];
  poc_payload: string;
  // misc lists
  refs: string[];
  tags: string[];
}

function emptyState(): FindingFormState {
  return {
    title: "",
    severity: "medium",
    confidence: "medium",
    kind: "manual",
    cwe: "",
    cve: "",
    cvss_vector: "",
    cvss_score: null,
    triage_status: "open",
    triage_note: "",
    summary: "",
    root_cause: "",
    attack_vector: "",
    business_impact: "",
    technical_details: "",
    fix: "",
    code_patch: "",
    references: [],
    ev_file: "",
    ev_start_line: "",
    ev_end_line: "",
    ev_snippet: "",
    poc_scenario: "",
    poc_steps: [],
    poc_payload: "",
    refs: [],
    tags: [],
  };
}

function stateFromFinding(f: Finding): FindingFormState {
  return {
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    kind: f.kind,
    cwe: f.cwe ?? "",
    cve: f.cve ?? "",
    cvss_vector: f.cvss_vector ?? "",
    cvss_score: f.cvss_score ?? null,
    triage_status: f.triage_status,
    triage_note: f.triage_note ?? "",
    summary: f.description.summary,
    root_cause: f.description.root_cause,
    attack_vector: f.description.attack_vector,
    business_impact: f.description.business_impact,
    technical_details: f.description.technical_details,
    fix: f.remediation.fix,
    code_patch: f.remediation.code_patch ?? "",
    references: [...f.remediation.references],
    ev_file: f.evidence?.file ?? "",
    ev_start_line: f.evidence?.start_line != null ? String(f.evidence.start_line) : "",
    ev_end_line: f.evidence?.end_line != null ? String(f.evidence.end_line) : "",
    ev_snippet: f.evidence?.snippet ?? "",
    poc_scenario: f.poc?.scenario ?? "",
    poc_steps: f.poc ? [...f.poc.exploitation_steps] : [],
    poc_payload: f.poc?.payload ?? "",
    refs: [...f.refs],
    tags: [...f.tags],
  };
}

function parseLineNumber(value: string): number | null {
  const n = parseInt(value.trim(), 10);
  return Number.isFinite(n) ? n : null;
}

/** Build an Evidence object, or null when every field is empty. */
function buildEvidence(s: FindingFormState): Evidence | null {
  const file = s.ev_file.trim() || null;
  const start = parseLineNumber(s.ev_start_line);
  const end = parseLineNumber(s.ev_end_line);
  const snippet = s.ev_snippet.trim() || null;
  if (!file && start == null && end == null && !snippet) return null;
  return { file, start_line: start, end_line: end, snippet };
}

/** Build a StructuredPoc, or null when empty. */
function buildPoc(s: FindingFormState): StructuredPoc | null {
  const scenario = s.poc_scenario.trim();
  const steps = s.poc_steps.map((x) => x.trim()).filter(Boolean);
  const payload = s.poc_payload.trim() || null;
  if (!scenario && steps.length === 0 && !payload) return null;
  return { scenario, exploitation_steps: steps, payload };
}

function cleanList(items: string[]): string[] {
  return items.map((x) => x.trim()).filter(Boolean);
}

function commonFields(s: FindingFormState) {
  return {
    severity: s.severity,
    confidence: s.confidence,
    kind: s.kind,
    cwe: s.cwe.trim() || null,
    cve: s.cve.trim() || null,
    cvss_vector: s.cvss_vector.trim() || null,
    cvss_score: s.cvss_vector.trim() ? s.cvss_score : null,
    triage_status: s.triage_status,
    triage_note: s.triage_note.trim() || null,
    description: {
      summary: s.summary,
      root_cause: s.root_cause,
      attack_vector: s.attack_vector,
      business_impact: s.business_impact,
      technical_details: s.technical_details,
    },
    remediation: {
      fix: s.fix,
      code_patch: s.code_patch.trim() || null,
      references: cleanList(s.references),
    },
    evidence: buildEvidence(s),
    poc: buildPoc(s),
    refs: cleanList(s.refs),
    tags: cleanList(s.tags),
  };
}

function toNewFinding(s: FindingFormState): NewFinding {
  return { title: s.title.trim(), ...commonFields(s) };
}

function toPatch(s: FindingFormState): FindingPatch {
  return { title: s.title.trim(), ...commonFields(s) };
}

// ── Small presentational helpers ─────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3 rounded-lg border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </h3>
      {children}
    </section>
  );
}

/** Add/remove list editor for string[] fields (references, steps, refs, tags). */
function ListEditor({
  label,
  items,
  placeholder,
  onChange,
  mono = false,
}: {
  label: string;
  items: string[];
  placeholder?: string;
  onChange: (next: string[]) => void;
  mono?: boolean;
}) {
  const { t } = useTranslation();
  const update = (i: number, value: string) =>
    onChange(items.map((it, idx) => (idx === i ? value : it)));
  const remove = (i: number) => onChange(items.filter((_, idx) => idx !== i));
  const add = () => onChange([...items, ""]);

  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <div className="space-y-2">
        <AnimatePresence initial={false}>
          {items.map((item, i) => (
            <motion.div
              key={i}
              layout
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: -8 }}
              transition={{ duration: 0.15 }}
              className="flex items-center gap-2"
            >
              <Input
                value={item}
                placeholder={placeholder}
                onChange={(e) => update(i, e.target.value)}
                className={mono ? "font-mono text-xs" : undefined}
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={() => remove(i)}
                aria-label={t("common.delete")}
              >
                <X />
              </Button>
            </motion.div>
          ))}
        </AnimatePresence>
        <Button type="button" variant="outline" size="sm" onClick={add}>
          <Plus />
          {t("findings.addRow")}
        </Button>
      </div>
    </div>
  );
}

export function FindingForm({
  open,
  onOpenChange,
  finding,
  onCreate,
  onUpdate,
  pending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  finding?: Finding;
  onCreate: (input: NewFinding) => void;
  onUpdate: (id: string, patch: FindingPatch) => void;
  pending: boolean;
}) {
  const { t } = useTranslation();
  const [state, setState] = useState<FindingFormState>(
    finding ? stateFromFinding(finding) : emptyState(),
  );

  const set = <K extends keyof FindingFormState>(key: K, value: FindingFormState[K]) =>
    setState((prev) => ({ ...prev, [key]: value }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!state.title.trim()) return;
    if (finding) onUpdate(finding.id, toPatch(state));
    else onCreate(toNewFinding(state));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {finding ? t("findings.editTitle") : t("findings.newTitle")}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* ── Classification ───────────────────────────────────────────── */}
          <Section title={t("findings.section.classification")}>
            <div className="space-y-1.5">
              <Label htmlFor="f-title">{t("findings.fieldTitle")}</Label>
              <Input
                id="f-title"
                autoFocus
                value={state.title}
                onChange={(e) => set("title", e.target.value)}
                placeholder={t("findings.fieldTitlePlaceholder")}
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <div className="space-y-1.5">
                <Label>{t("findings.fieldSeverity")}</Label>
                <Select value={state.severity} onValueChange={(v) => set("severity", v as Severity)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {t(`severity.${s}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>{t("findings.fieldConfidence")}</Label>
                <Select
                  value={state.confidence}
                  onValueChange={(v) => set("confidence", v as Confidence)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CONFIDENCES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {t(`confidence.${c}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>{t("findings.fieldKind")}</Label>
                <Select value={state.kind} onValueChange={(v) => set("kind", v as FindingKind)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {KINDS.map((k) => (
                      <SelectItem key={k} value={k}>
                        {t(`kind.${k}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>{t("findings.fieldTriageStatus")}</Label>
                <Select
                  value={state.triage_status}
                  onValueChange={(v) => set("triage_status", v as TriageStatus)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TRIAGE.map((tr) => (
                      <SelectItem key={tr} value={tr}>
                        {t(`triage.${tr}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="f-cwe">{t("findings.fieldCwe")}</Label>
                <Input
                  id="f-cwe"
                  value={state.cwe}
                  onChange={(e) => set("cwe", e.target.value)}
                  placeholder={t("findings.fieldCwePlaceholder")}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="f-cve">{t("findings.fieldCve")}</Label>
                <Input
                  id="f-cve"
                  value={state.cve}
                  onChange={(e) => set("cve", e.target.value)}
                  placeholder={t("findings.fieldCvePlaceholder")}
                  className="font-mono"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="f-triage-note">{t("findings.fieldTriageNote")}</Label>
              <Textarea
                id="f-triage-note"
                rows={2}
                value={state.triage_note}
                onChange={(e) => set("triage_note", e.target.value)}
                placeholder={t("findings.fieldTriageNotePlaceholder")}
              />
            </div>
          </Section>

          {/* ── CVSS ──────────────────────────────────────────────────────── */}
          <Section title={t("findings.section.cvss")}>
            <CvssCalculator
              vector={state.cvss_vector || null}
              onChange={({ vector, score }) => {
                setState((prev) => ({ ...prev, cvss_vector: vector, cvss_score: score }));
              }}
            />
          </Section>

          {/* ── Description ───────────────────────────────────────────────── */}
          <Section title={t("findings.section.description")}>
            <div className="space-y-1.5">
              <Label htmlFor="f-summary">{t("findings.fieldSummary")}</Label>
              <Textarea
                id="f-summary"
                value={state.summary}
                onChange={(e) => set("summary", e.target.value)}
                placeholder={t("findings.fieldSummaryPlaceholder")}
              />
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="f-root">{t("findings.fieldRootCause")}</Label>
                <Textarea
                  id="f-root"
                  value={state.root_cause}
                  onChange={(e) => set("root_cause", e.target.value)}
                  placeholder={t("findings.fieldRootCausePlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="f-vector">{t("findings.fieldAttackVector")}</Label>
                <Textarea
                  id="f-vector"
                  value={state.attack_vector}
                  onChange={(e) => set("attack_vector", e.target.value)}
                  placeholder={t("findings.fieldAttackVectorPlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="f-impact">{t("findings.fieldBusinessImpact")}</Label>
                <Textarea
                  id="f-impact"
                  value={state.business_impact}
                  onChange={(e) => set("business_impact", e.target.value)}
                  placeholder={t("findings.fieldBusinessImpactPlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="f-tech">{t("findings.fieldTechnicalDetails")}</Label>
                <Textarea
                  id="f-tech"
                  value={state.technical_details}
                  onChange={(e) => set("technical_details", e.target.value)}
                  placeholder={t("findings.fieldTechnicalDetailsPlaceholder")}
                />
              </div>
            </div>
          </Section>

          {/* ── Evidence ──────────────────────────────────────────────────── */}
          <Section title={t("findings.section.evidence")}>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="space-y-1.5 md:col-span-1">
                <Label htmlFor="f-ev-file">{t("findings.fieldEvidenceFile")}</Label>
                <Input
                  id="f-ev-file"
                  value={state.ev_file}
                  onChange={(e) => set("ev_file", e.target.value)}
                  placeholder={t("findings.fieldEvidenceFilePlaceholder")}
                  className="font-mono text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="f-ev-start">{t("findings.fieldEvidenceStartLine")}</Label>
                <Input
                  id="f-ev-start"
                  type="number"
                  min={0}
                  value={state.ev_start_line}
                  onChange={(e) => set("ev_start_line", e.target.value)}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="f-ev-end">{t("findings.fieldEvidenceEndLine")}</Label>
                <Input
                  id="f-ev-end"
                  type="number"
                  min={0}
                  value={state.ev_end_line}
                  onChange={(e) => set("ev_end_line", e.target.value)}
                  className="font-mono"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="f-ev-snippet">{t("findings.fieldEvidenceSnippet")}</Label>
              <Textarea
                id="f-ev-snippet"
                value={state.ev_snippet}
                onChange={(e) => set("ev_snippet", e.target.value)}
                placeholder={t("findings.fieldEvidenceSnippetPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
          </Section>

          {/* ── Proof of concept ──────────────────────────────────────────── */}
          <Section title={t("findings.section.poc")}>
            <div className="space-y-1.5">
              <Label htmlFor="f-poc-scenario">{t("findings.fieldPocScenario")}</Label>
              <Textarea
                id="f-poc-scenario"
                value={state.poc_scenario}
                onChange={(e) => set("poc_scenario", e.target.value)}
                placeholder={t("findings.fieldPocScenarioPlaceholder")}
              />
            </div>
            <ListEditor
              label={t("findings.fieldPocSteps")}
              items={state.poc_steps}
              placeholder={t("findings.fieldPocStepsPlaceholder")}
              onChange={(next) => set("poc_steps", next)}
            />
            <div className="space-y-1.5">
              <Label htmlFor="f-poc-payload">{t("findings.fieldPocPayload")}</Label>
              <Textarea
                id="f-poc-payload"
                value={state.poc_payload}
                onChange={(e) => set("poc_payload", e.target.value)}
                placeholder={t("findings.fieldPocPayloadPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
          </Section>

          {/* ── Remediation ───────────────────────────────────────────────── */}
          <Section title={t("findings.section.remediation")}>
            <div className="space-y-1.5">
              <Label htmlFor="f-fix">{t("findings.fieldFix")}</Label>
              <Textarea
                id="f-fix"
                value={state.fix}
                onChange={(e) => set("fix", e.target.value)}
                placeholder={t("findings.fieldFixPlaceholder")}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="f-patch">{t("findings.fieldCodePatch")}</Label>
              <Textarea
                id="f-patch"
                value={state.code_patch}
                onChange={(e) => set("code_patch", e.target.value)}
                placeholder={t("findings.fieldCodePatchPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
            <ListEditor
              label={t("findings.fieldRemediationRefs")}
              items={state.references}
              placeholder={t("findings.fieldRefPlaceholder")}
              onChange={(next) => set("references", next)}
              mono
            />
          </Section>

          {/* ── References & tags ─────────────────────────────────────────── */}
          <Section title={t("findings.section.metadata")}>
            <ListEditor
              label={t("findings.fieldRefs")}
              items={state.refs}
              placeholder={t("findings.fieldRefPlaceholder")}
              onChange={(next) => set("refs", next)}
              mono
            />
            <ListEditor
              label={t("findings.fieldTags")}
              items={state.tags}
              placeholder={t("findings.fieldTagPlaceholder")}
              onChange={(next) => set("tags", next)}
            />
          </Section>

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="brand" disabled={pending || !state.title.trim()}>
              {pending ? t("common.saving") : t("common.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
