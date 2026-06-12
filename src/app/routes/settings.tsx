import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { ArrowLeft, KeyRound, Save, ShieldCheck, RotateCcw, HardDriveDownload } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { save } from "@tauri-apps/plugin-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { asIpcError, backupVault, changePassphrase } from "@/lib/ipc";
import {
  useResetTemplate,
  useSaveTemplate,
  useTemplate,
  useTemplates,
} from "@/lib/queries/use-templates";
import type { ReportType } from "@/lib/types";

const MIN_PASSPHRASE = 8;

function SecuritySection() {
  const { t } = useTranslation();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [changing, setChanging] = useState(false);
  const [backing, setBacking] = useState(false);

  const handleChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next.length < MIN_PASSPHRASE) {
      toast.error(t("vault.tooShort"));
      return;
    }
    if (next !== confirm) {
      toast.error(t("vault.mismatch"));
      return;
    }
    setChanging(true);
    try {
      await changePassphrase(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast.success(t("settings.security.changeSuccess"));
    } catch (err) {
      toast.error(asIpcError(err).message || t("settings.security.changeError"));
    } finally {
      setChanging(false);
    }
  };

  const handleBackup = async () => {
    setBacking(true);
    try {
      const path = await save({
        defaultPath: "pwn2report-backup.db",
        filters: [{ name: t("settings.security.vaultFile"), extensions: ["db"] }],
      });
      if (!path) {
        setBacking(false);
        return;
      }
      await backupVault(path);
      toast.success(t("settings.security.backupSuccess"));
    } catch (err) {
      toast.error(asIpcError(err).message || t("settings.security.backupError"));
    } finally {
      setBacking(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="size-4 text-[hsl(var(--accent-brand))]" />
          {t("settings.security.title")}
        </CardTitle>
        <CardDescription>{t("settings.security.subtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <form onSubmit={handleChange} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="s-current">{t("settings.security.current")}</Label>
            <Input
              id="s-current"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="s-new">{t("settings.security.new")}</Label>
              <Input
                id="s-new"
                type="password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                autoComplete="new-password"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="s-confirm">{t("settings.security.confirm")}</Label>
              <Input
                id="s-confirm"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="new-password"
                required
              />
            </div>
          </div>
          <Button
            type="submit"
            variant="brand"
            disabled={changing || !current || !next || !confirm}
          >
            <KeyRound />
            {changing ? t("common.saving") : t("settings.security.changeCta")}
          </Button>
        </form>

        <Separator />

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium">{t("settings.security.backupTitle")}</p>
            <p className="text-sm text-muted-foreground">{t("settings.security.backupHint")}</p>
          </div>
          <Button variant="outline" onClick={handleBackup} disabled={backing}>
            <HardDriveDownload />
            {backing ? t("settings.security.backingUp") : t("settings.security.backupCta")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function TemplatesSection() {
  const { t } = useTranslation();
  const { data: templates, isLoading } = useTemplates();
  const [selected, setSelected] = useState<ReportType | undefined>(undefined);
  const { data: source } = useTemplate(selected);
  const [draft, setDraft] = useState("");
  const saveTemplate = useSaveTemplate();
  const resetTemplate = useResetTemplate();

  // Default selection to the first available report type.
  useEffect(() => {
    if (!selected && templates && templates.length > 0) {
      setSelected(templates[0].report_type);
    }
  }, [templates, selected]);

  // Load fetched source into the editable draft.
  useEffect(() => {
    if (source != null) setDraft(source);
  }, [source]);

  const currentInfo = templates?.find((tpl) => tpl.report_type === selected);

  const handleSave = () => {
    if (!selected) return;
    saveTemplate.mutate(
      { reportType: selected, content: draft },
      {
        onSuccess: () => toast.success(t("settings.templates.saveSuccess")),
        onError: (err) => toast.error(asIpcError(err).message || t("settings.templates.saveError")),
      },
    );
  };

  const handleReset = () => {
    if (!selected) return;
    if (!window.confirm(t("settings.templates.resetConfirm"))) return;
    resetTemplate.mutate(selected, {
      onSuccess: () => toast.success(t("settings.templates.resetSuccess")),
      onError: (err) => toast.error(asIpcError(err).message || t("settings.templates.resetError")),
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("settings.templates.title")}</CardTitle>
        <CardDescription>{t("settings.templates.subtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
        ) : !templates || templates.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("settings.templates.empty")}</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3">
              <div className="w-56 space-y-1.5">
                <Label>{t("settings.templates.reportType")}</Label>
                <Select
                  value={selected}
                  onValueChange={(v) => setSelected(v as ReportType)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {templates.map((tpl) => (
                      <SelectItem key={tpl.report_type} value={tpl.report_type}>
                        {t(`reportType.${tpl.report_type}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {currentInfo && (
                <Badge
                  variant={currentInfo.is_custom ? "default" : "secondary"}
                  className="mt-6"
                >
                  {currentInfo.is_custom
                    ? t("settings.templates.custom")
                    : t("settings.templates.default")}
                </Badge>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="tpl-editor">{t("settings.templates.source")}</Label>
              <Textarea
                id="tpl-editor"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                spellCheck={false}
                rows={20}
                className="font-mono text-xs leading-relaxed"
                style={{ fontFamily: "var(--font-mono)" }}
              />
            </div>

            <div className="flex items-center gap-2">
              <Button variant="brand" onClick={handleSave} disabled={saveTemplate.isPending}>
                <Save />
                {saveTemplate.isPending ? t("common.saving") : t("common.save")}
              </Button>
              <Button
                variant="outline"
                onClick={handleReset}
                disabled={resetTemplate.isPending || !currentInfo?.is_custom}
              >
                <RotateCcw />
                {t("settings.templates.resetCta")}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function Settings() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
      className="mx-auto max-w-3xl px-6 py-8"
    >
      <div className="mb-6">
        <Button variant="ghost" onClick={() => navigate("/")}>
          <ArrowLeft />
          {t("common.back")}
        </Button>
      </div>

      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">{t("settings.title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("settings.subtitle")}</p>
      </header>

      <div className="space-y-6">
        <SecuritySection />
        <TemplatesSection />
      </div>
    </motion.div>
  );
}
