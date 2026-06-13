import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ChevronDown, Plus, X } from "lucide-react";
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
import { EvidenceGallery } from "@/components/evidence/evidence-gallery";
import { FindingAssetsField } from "@/components/findings/finding-assets-field";
import { MappingsEditor } from "@/components/findings/mappings-editor";
import { KeyValueEditor } from "@/components/ui/key-value-editor";
import { AiAssistButton } from "@/components/ai/ai-assist-button";
import { cn } from "@/lib/utils";
import { useSubmitShortcut } from "@/lib/use-hotkeys";
import { useFindingAssets } from "@/lib/queries/use-finding-assets";
import {
  emptyState,
  stateFromFinding,
  toNewFinding,
  toPatch,
  type FindingFormState,
} from "@/components/findings/finding-form-state";
import {
  hasBlockingError,
  issuesByField,
  validateFindingForm,
  type FieldIssue,
} from "@/lib/finding-validation";
import { clearDraft, draftKey, loadDraft, saveDraft } from "@/lib/finding-draft";
import type {
  Confidence,
  Finding,
  FindingKind,
  FindingPatch,
  NewFinding,
  RetestStatus,
  Severity,
  TriageStatus,
} from "@/lib/types";

export type { FindingFormState } from "@/components/findings/finding-form-state";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES: Confidence[] = ["high", "medium", "low"];
const KINDS: FindingKind[] = ["manual", "sast", "iac", "sca", "secret"];
const TRIAGE: TriageStatus[] = ["open", "acknowledged", "false_positive", "resolved"];
const RETEST: RetestStatus[] = [
  "not_retested",
  "fixed",
  "partially_fixed",
  "not_fixed",
  "risk_accepted",
];

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

/**
 * A collapsible variant of `Section` for optional, lower-traffic groups (retest,
 * mappings, custom fields) so the form stays light by default.
 */
function CollapsibleFormSection({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="rounded-lg border">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 p-4 text-left"
      >
        <ChevronDown
          className={cn(
            "size-4 text-muted-foreground transition-transform",
            open ? "rotate-0" : "-rotate-90",
          )}
        />
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {title}
        </span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="space-y-3 px-4 pb-4">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}

/** Inline field error/warning message, wired up via the field's aria-describedby. */
function FieldError({ id, issue }: { id: string; issue?: FieldIssue }) {
  const { t } = useTranslation();
  if (!issue) return null;
  return (
    <p
      id={id}
      className={
        issue.severity === "error"
          ? "text-xs text-destructive"
          : "text-xs text-amber-600 dark:text-amber-500"
      }
    >
      {t(issue.messageKey)}
    </p>
  );
}

/**
 * A labelled Textarea with an AI assist button next to the label. The assist
 * button only renders when AI assistance is enabled (handled internally).
 */
function AiTextarea({
  id,
  label,
  value,
  placeholder,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  placeholder?: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={id}>{label}</Label>
        <AiAssistButton
          value={value}
          fieldLabel={label}
          onResult={onChange}
          className="-my-2 size-7"
        />
      </div>
      <Textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

/** A single list row with a stable id (so reordering/deleting keeps focus right). */
interface ListRow {
  id: string;
  value: string;
}

function newRowId(): string {
  // crypto.randomUUID is available in modern browsers / the Tauri webview.
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `row-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

/**
 * Add/remove list editor for string[] fields (references, steps, refs, tags).
 *
 * Rows are keyed by a stable generated id rather than the array index, so
 * deleting or reordering a middle row doesn't mis-focus or mis-animate the
 * remaining rows. The parent still owns a plain string[]; we keep a local
 * id↔value mapping in sync with it.
 */
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
  // Local rows carry stable ids. We reconcile against the incoming `items` so
  // external changes (draft restore, AI, reset) stay reflected without losing
  // the id of rows whose value is unchanged.
  const [rows, setRows] = useState<ListRow[]>(() =>
    items.map((value) => ({ id: newRowId(), value })),
  );

  // Reconcile when `items` changes from outside (length or value mismatch).
  useEffect(() => {
    setRows((prev) => {
      const sameLength = prev.length === items.length;
      const sameValues = sameLength && prev.every((r, i) => r.value === items[i]);
      if (sameValues) return prev;
      return items.map((value, i) => ({ id: prev[i]?.id ?? newRowId(), value }));
    });
  }, [items]);

  const commit = (next: ListRow[]) => {
    setRows(next);
    onChange(next.map((r) => r.value));
  };

  const update = (id: string, value: string) =>
    commit(rows.map((r) => (r.id === id ? { ...r, value } : r)));
  const remove = (id: string) => commit(rows.filter((r) => r.id !== id));
  const add = () => commit([...rows, { id: newRowId(), value: "" }]);

  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <div className="space-y-2">
        <AnimatePresence initial={false}>
          {rows.map((row) => (
            <motion.div
              key={row.id}
              layout
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: -8 }}
              transition={{ duration: 0.15 }}
              className="flex items-center gap-2"
            >
              <Input
                value={row.value}
                placeholder={placeholder}
                onChange={(e) => update(row.id, e.target.value)}
                className={mono ? "font-mono text-xs" : undefined}
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={() => remove(row.id)}
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
  reportId,
  finding,
  onCreate,
  onUpdate,
  pending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Report this finding belongs to — used to key per-report "new" drafts. */
  reportId: string;
  finding?: Finding;
  /** `assetIds` is the set of report assets this finding affects, persisted by
   * the parent once the finding id is known (after create / on update). */
  onCreate: (input: NewFinding, assetIds: string[]) => void;
  onUpdate: (id: string, patch: FindingPatch, assetIds: string[]) => void;
  pending: boolean;
}) {
  const { t } = useTranslation();

  // Affected-assets selection. Loaded for an existing finding; empty for new.
  const { data: findingAssets } = useFindingAssets(finding?.id);
  const [assetIds, setAssetIds] = useState<string[]>([]);
  // Sync the loaded selection in (only for the finding under edit).
  useEffect(() => {
    if (findingAssets) setAssetIds(findingAssets.map((a) => a.id));
  }, [findingAssets]);

  // The pristine baseline for dirty-tracking: the finding under edit, or empty.
  const initial = useMemo<FindingFormState>(
    () => (finding ? stateFromFinding(finding) : emptyState()),
    [finding],
  );
  const key = useMemo(() => draftKey(finding?.id, reportId), [finding?.id, reportId]);

  // Restore an in-progress draft (if any) over the baseline on first mount.
  const [state, setState] = useState<FindingFormState>(() => loadDraft(key) ?? initial);
  const [confirmDiscard, setConfirmDiscard] = useState(false);

  const set = <K extends keyof FindingFormState>(k: K, value: FindingFormState[K]) =>
    setState((prev) => ({ ...prev, [k]: value }));

  // Dirty = current state differs from the pristine baseline.
  const dirty = useMemo(
    () => JSON.stringify(state) !== JSON.stringify(initial),
    [state, initial],
  );

  // Persist / clear the draft as the user types. Only persist when dirty so we
  // don't leave a stale draft equal to the saved finding.
  useEffect(() => {
    if (!open) return;
    if (dirty) saveDraft(key, state);
    else clearDraft(key);
  }, [open, dirty, key, state]);

  // Validation (recomputed cheaply on each render via memo).
  const issues = useMemo(() => validateFindingForm(state), [state]);
  const fieldIssues = useMemo(() => issuesByField(issues), [issues]);
  const blocked = hasBlockingError(issues);

  // Guard the close path: if dirty, ask before discarding.
  const requestClose = () => {
    if (dirty) setConfirmDiscard(true);
    else onOpenChange(false);
  };

  const confirmDiscardClose = () => {
    clearDraft(key);
    setConfirmDiscard(false);
    onOpenChange(false);
  };

  // Wrap the success path so callers' close clears the draft. We can't observe
  // the mutation here, so we clear the draft optimistically on submit; if the
  // save fails, the form stays open and the next keystroke re-saves the draft.
  const submittedRef = useRef(false);
  useEffect(() => {
    // When the dialog closes after a submit attempt, the parent owns success.
    if (!open && submittedRef.current) submittedRef.current = false;
  }, [open]);

  const submit = () => {
    if (blocked || pending) return;
    submittedRef.current = true;
    clearDraft(key);
    if (finding) onUpdate(finding.id, toPatch(state), assetIds);
    else onCreate(toNewFinding(state), assetIds);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    submit();
  };

  // Cmd/Ctrl+Enter submits from anywhere in the dialog (only while the discard
  // guard is not up).
  useSubmitShortcut(open && !confirmDiscard, submit);

  return (
    <>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (next) onOpenChange(true);
          else requestClose();
        }}
      >
        <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {finding ? t("findings.editTitle") : t("findings.newTitle")}
            </DialogTitle>
            <DialogDescription className="sr-only">
              {finding ? t("findings.editTitle") : t("findings.newTitle")}
            </DialogDescription>
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
                  aria-invalid={fieldIssues["f-title"] ? true : undefined}
                  aria-describedby={fieldIssues["f-title"] ? "f-title-err" : undefined}
                />
                <FieldError id="f-title-err" issue={fieldIssues["f-title"]} />
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
                    aria-invalid={fieldIssues["f-cwe"] ? true : undefined}
                    aria-describedby={fieldIssues["f-cwe"] ? "f-cwe-err" : undefined}
                  />
                  <FieldError id="f-cwe-err" issue={fieldIssues["f-cwe"]} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="f-cve">{t("findings.fieldCve")}</Label>
                  <Input
                    id="f-cve"
                    value={state.cve}
                    onChange={(e) => set("cve", e.target.value)}
                    placeholder={t("findings.fieldCvePlaceholder")}
                    className="font-mono"
                    aria-invalid={fieldIssues["f-cve"] ? true : undefined}
                    aria-describedby={fieldIssues["f-cve"] ? "f-cve-err" : undefined}
                  />
                  <FieldError id="f-cve-err" issue={fieldIssues["f-cve"]} />
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
              <AiTextarea
                id="f-summary"
                label={t("findings.fieldSummary")}
                value={state.summary}
                onChange={(v) => set("summary", v)}
                placeholder={t("findings.fieldSummaryPlaceholder")}
              />
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <AiTextarea
                  id="f-root"
                  label={t("findings.fieldRootCause")}
                  value={state.root_cause}
                  onChange={(v) => set("root_cause", v)}
                  placeholder={t("findings.fieldRootCausePlaceholder")}
                />
                <AiTextarea
                  id="f-vector"
                  label={t("findings.fieldAttackVector")}
                  value={state.attack_vector}
                  onChange={(v) => set("attack_vector", v)}
                  placeholder={t("findings.fieldAttackVectorPlaceholder")}
                />
                <AiTextarea
                  id="f-impact"
                  label={t("findings.fieldBusinessImpact")}
                  value={state.business_impact}
                  onChange={(v) => set("business_impact", v)}
                  placeholder={t("findings.fieldBusinessImpactPlaceholder")}
                />
                <AiTextarea
                  id="f-tech"
                  label={t("findings.fieldTechnicalDetails")}
                  value={state.technical_details}
                  onChange={(v) => set("technical_details", v)}
                  placeholder={t("findings.fieldTechnicalDetailsPlaceholder")}
                />
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
                    aria-invalid={fieldIssues["f-ev-start"] ? true : undefined}
                    aria-describedby={fieldIssues["f-ev-start"] ? "f-ev-start-err" : undefined}
                  />
                  <FieldError id="f-ev-start-err" issue={fieldIssues["f-ev-start"]} />
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
                    aria-invalid={fieldIssues["f-ev-end"] ? true : undefined}
                    aria-describedby={fieldIssues["f-ev-end"] ? "f-ev-end-err" : undefined}
                  />
                  <FieldError id="f-ev-end-err" issue={fieldIssues["f-ev-end"]} />
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

            {/* ── Evidence images ───────────────────────────────────────────── */}
            <Section title={t("evidence.section")}>
              {finding ? (
                <EvidenceGallery findingId={finding.id} />
              ) : (
                <p className="text-sm text-muted-foreground">{t("evidence.saveFirst")}</p>
              )}
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
              <AiTextarea
                id="f-fix"
                label={t("findings.fieldFix")}
                value={state.fix}
                onChange={(v) => set("fix", v)}
                placeholder={t("findings.fieldFixPlaceholder")}
              />
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
              <FindingAssetsField
                reportId={reportId}
                selected={assetIds}
                onChange={setAssetIds}
              />
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

            {/* ── Retest ────────────────────────────────────────────────────── */}
            <CollapsibleFormSection title={t("findings.section.retest")}>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>{t("findings.fieldRetestStatus")}</Label>
                  <Select
                    value={state.retest_status}
                    onValueChange={(v) => set("retest_status", v as RetestStatus)}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {RETEST.map((r) => (
                        <SelectItem key={r} value={r}>
                          {t(`retest.${r}`)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="f-retest-date">{t("findings.fieldRetestDate")}</Label>
                  <Input
                    id="f-retest-date"
                    type="date"
                    value={state.retest_date}
                    onChange={(e) => set("retest_date", e.target.value)}
                    disabled={state.retest_status === "not_retested"}
                  />
                </div>
              </div>
            </CollapsibleFormSection>

            {/* ── Compliance mappings ───────────────────────────────────────── */}
            <CollapsibleFormSection title={t("findings.section.mappings")}>
              <MappingsEditor
                value={state.mappings}
                onChange={(next) => set("mappings", next)}
              />
            </CollapsibleFormSection>

            {/* ── Custom fields ─────────────────────────────────────────────── */}
            <CollapsibleFormSection title={t("findings.section.customFields")}>
              <KeyValueEditor
                value={state.custom_fields}
                onChange={(next) => set("custom_fields", next)}
              />
            </CollapsibleFormSection>

            <DialogFooter>
              <Button type="button" variant="ghost" onClick={requestClose}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" variant="brand" disabled={pending || blocked}>
                {pending ? t("common.saving") : t("common.save")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Discard-confirmation guard for unsaved changes. */}
      <Dialog open={confirmDiscard} onOpenChange={setConfirmDiscard}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t("findings.discard.title")}</DialogTitle>
            <DialogDescription>{t("findings.discard.body")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setConfirmDiscard(false)}>
              {t("findings.discard.keepEditing")}
            </Button>
            <Button type="button" variant="destructive" onClick={confirmDiscardClose}>
              {t("findings.discard.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
