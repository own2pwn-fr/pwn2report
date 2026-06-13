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
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { CvssCalculator } from "@/components/cvss-calculator";
import { useSubmitShortcut } from "@/lib/use-hotkeys";
import type {
  Confidence,
  FindingKind,
  KbEntry,
  KbPatch,
  NewKbEntry,
  Severity,
} from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES: Confidence[] = ["high", "medium", "low"];
const KINDS: FindingKind[] = ["manual", "sast", "iac", "sca", "secret"];

interface KbFormState {
  title: string;
  severity: Severity;
  confidence: Confidence;
  kind: FindingKind;
  cwe: string;
  cve: string;
  cvss_vector: string;
  cvss_score: number | null;
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
  tags: string[];
}

function emptyState(): KbFormState {
  return {
    title: "",
    severity: "medium",
    confidence: "medium",
    kind: "manual",
    cwe: "",
    cve: "",
    cvss_vector: "",
    cvss_score: null,
    summary: "",
    root_cause: "",
    attack_vector: "",
    business_impact: "",
    technical_details: "",
    fix: "",
    code_patch: "",
    references: [],
    tags: [],
  };
}

function stateFromEntry(e: KbEntry): KbFormState {
  return {
    title: e.title,
    severity: e.severity,
    confidence: e.confidence,
    kind: e.kind,
    cwe: e.cwe ?? "",
    cve: e.cve ?? "",
    cvss_vector: e.cvss_vector ?? "",
    cvss_score: e.cvss_score ?? null,
    summary: e.description.summary,
    root_cause: e.description.root_cause,
    attack_vector: e.description.attack_vector,
    business_impact: e.description.business_impact,
    technical_details: e.description.technical_details,
    fix: e.remediation.fix,
    code_patch: e.remediation.code_patch ?? "",
    references: [...e.remediation.references],
    tags: [...e.tags],
  };
}

function cleanList(items: string[]): string[] {
  return items.map((x) => x.trim()).filter(Boolean);
}

function toNewEntry(s: KbFormState): NewKbEntry {
  return {
    title: s.title.trim(),
    severity: s.severity,
    confidence: s.confidence,
    kind: s.kind,
    cwe: s.cwe.trim() || null,
    cve: s.cve.trim() || null,
    cvss_vector: s.cvss_vector.trim() || null,
    cvss_score: s.cvss_vector.trim() ? s.cvss_score : null,
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
    tags: cleanList(s.tags),
  };
}

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

export function KbForm({
  open,
  onOpenChange,
  entry,
  onCreate,
  onUpdate,
  pending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  entry?: KbEntry;
  onCreate: (input: NewKbEntry) => void;
  onUpdate: (id: string, patch: KbPatch) => void;
  pending: boolean;
}) {
  const { t } = useTranslation();
  const [state, setState] = useState<KbFormState>(
    entry ? stateFromEntry(entry) : emptyState(),
  );

  const set = <K extends keyof KbFormState>(key: K, value: KbFormState[K]) =>
    setState((prev) => ({ ...prev, [key]: value }));

  const submit = () => {
    if (!state.title.trim()) return;
    if (entry) onUpdate(entry.id, toNewEntry(state));
    else onCreate(toNewEntry(state));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    submit();
  };

  useSubmitShortcut(open, submit);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{entry ? t("kb.editTitle") : t("kb.newTitle")}</DialogTitle>
          <DialogDescription>{t("kb.subtitle")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* ── Classification ───────────────────────────────────────────── */}
          <Section title={t("findings.section.classification")}>
            <div className="space-y-1.5">
              <Label htmlFor="kb-title">{t("findings.fieldTitle")}</Label>
              <Input
                id="kb-title"
                autoFocus
                value={state.title}
                onChange={(e) => set("title", e.target.value)}
                placeholder={t("findings.fieldTitlePlaceholder")}
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
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
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="kb-cwe">{t("findings.fieldCwe")}</Label>
                <Input
                  id="kb-cwe"
                  value={state.cwe}
                  onChange={(e) => set("cwe", e.target.value)}
                  placeholder={t("findings.fieldCwePlaceholder")}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="kb-cve">{t("findings.fieldCve")}</Label>
                <Input
                  id="kb-cve"
                  value={state.cve}
                  onChange={(e) => set("cve", e.target.value)}
                  placeholder={t("findings.fieldCvePlaceholder")}
                  className="font-mono"
                />
              </div>
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
              <Label htmlFor="kb-summary">{t("findings.fieldSummary")}</Label>
              <Textarea
                id="kb-summary"
                value={state.summary}
                onChange={(e) => set("summary", e.target.value)}
                placeholder={t("findings.fieldSummaryPlaceholder")}
              />
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="kb-root">{t("findings.fieldRootCause")}</Label>
                <Textarea
                  id="kb-root"
                  value={state.root_cause}
                  onChange={(e) => set("root_cause", e.target.value)}
                  placeholder={t("findings.fieldRootCausePlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="kb-vector">{t("findings.fieldAttackVector")}</Label>
                <Textarea
                  id="kb-vector"
                  value={state.attack_vector}
                  onChange={(e) => set("attack_vector", e.target.value)}
                  placeholder={t("findings.fieldAttackVectorPlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="kb-impact">{t("findings.fieldBusinessImpact")}</Label>
                <Textarea
                  id="kb-impact"
                  value={state.business_impact}
                  onChange={(e) => set("business_impact", e.target.value)}
                  placeholder={t("findings.fieldBusinessImpactPlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="kb-tech">{t("findings.fieldTechnicalDetails")}</Label>
                <Textarea
                  id="kb-tech"
                  value={state.technical_details}
                  onChange={(e) => set("technical_details", e.target.value)}
                  placeholder={t("findings.fieldTechnicalDetailsPlaceholder")}
                />
              </div>
            </div>
          </Section>

          {/* ── Remediation ───────────────────────────────────────────────── */}
          <Section title={t("findings.section.remediation")}>
            <div className="space-y-1.5">
              <Label htmlFor="kb-fix">{t("findings.fieldFix")}</Label>
              <Textarea
                id="kb-fix"
                value={state.fix}
                onChange={(e) => set("fix", e.target.value)}
                placeholder={t("findings.fieldFixPlaceholder")}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-patch">{t("findings.fieldCodePatch")}</Label>
              <Textarea
                id="kb-patch"
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

          {/* ── Tags ──────────────────────────────────────────────────────── */}
          <Section title={t("findings.section.metadata")}>
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
