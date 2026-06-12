import { useState } from "react";
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
import type {
  Confidence,
  Finding,
  FindingPatch,
  NewFinding,
  Severity,
} from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES: Confidence[] = ["high", "medium", "low"];

export interface FindingFormState {
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  cve: string;
  cvss_vector: string;
  summary: string;
  root_cause: string;
  attack_vector: string;
  business_impact: string;
  technical_details: string;
  fix: string;
}

function emptyState(): FindingFormState {
  return {
    title: "",
    severity: "medium",
    confidence: "medium",
    cwe: "",
    cve: "",
    cvss_vector: "",
    summary: "",
    root_cause: "",
    attack_vector: "",
    business_impact: "",
    technical_details: "",
    fix: "",
  };
}

function stateFromFinding(f: Finding): FindingFormState {
  return {
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    cwe: f.cwe ?? "",
    cve: f.cve ?? "",
    cvss_vector: f.cvss_vector ?? "",
    summary: f.description.summary,
    root_cause: f.description.root_cause,
    attack_vector: f.description.attack_vector,
    business_impact: f.description.business_impact,
    technical_details: f.description.technical_details,
    fix: f.remediation.fix,
  };
}

/** Build a NewFinding payload (create). */
function toNewFinding(s: FindingFormState): NewFinding {
  return {
    title: s.title.trim(),
    severity: s.severity,
    confidence: s.confidence,
    cwe: s.cwe.trim() || null,
    cve: s.cve.trim() || null,
    cvss_vector: s.cvss_vector.trim() || null,
    description: {
      summary: s.summary,
      root_cause: s.root_cause,
      attack_vector: s.attack_vector,
      business_impact: s.business_impact,
      technical_details: s.technical_details,
    },
    remediation: { fix: s.fix },
  };
}

/** Build a FindingPatch payload (edit). */
function toPatch(s: FindingFormState, original: Finding): FindingPatch {
  return {
    title: s.title.trim(),
    severity: s.severity,
    confidence: s.confidence,
    cwe: s.cwe.trim() || null,
    cve: s.cve.trim() || null,
    cvss_vector: s.cvss_vector.trim() || null,
    description: {
      summary: s.summary,
      root_cause: s.root_cause,
      attack_vector: s.attack_vector,
      business_impact: s.business_impact,
      technical_details: s.technical_details,
    },
    remediation: { ...original.remediation, fix: s.fix },
  };
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

  // Re-seed when the target finding changes (form is keyed by it in the parent).
  const set = <K extends keyof FindingFormState>(key: K, value: FindingFormState[K]) =>
    setState((prev) => ({ ...prev, [key]: value }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!state.title.trim()) return;
    if (finding) onUpdate(finding.id, toPatch(state, finding));
    else onCreate(toNewFinding(state));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {finding ? t("findings.editTitle") : t("findings.newTitle")}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
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

          <div className="grid grid-cols-2 gap-4">
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
            <Label htmlFor="f-cvss">{t("findings.fieldCvssVector")}</Label>
            <Input
              id="f-cvss"
              value={state.cvss_vector}
              onChange={(e) => set("cvss_vector", e.target.value)}
              placeholder={t("findings.fieldCvssVectorPlaceholder")}
              className="font-mono text-xs"
            />
          </div>

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

          <div className="space-y-1.5">
            <Label htmlFor="f-fix">{t("findings.fieldFix")}</Label>
            <Textarea
              id="f-fix"
              value={state.fix}
              onChange={(e) => set("fix", e.target.value)}
              placeholder={t("findings.fieldFixPlaceholder")}
            />
          </div>

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
