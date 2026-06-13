import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  KeyRound,
  Save,
  ShieldCheck,
  RotateCcw,
  HardDriveDownload,
  Sparkles,
  Plug,
  Palette,
  RefreshCw,
  Upload,
  Download,
  AlertTriangle,
  ListPlus,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { open, save } from "@tauri-apps/plugin-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { ThemeToggle } from "@/components/theme-toggle";
import { backupVault, changePassphrase, errorMessage } from "@/lib/ipc";
import {
  useResetTemplate,
  useSaveTemplate,
  useTemplate,
  useTemplates,
} from "@/lib/queries/use-templates";
import {
  useAiConfig,
  useAiModels,
  useSaveAiConfig,
  useTestAiConnection,
} from "@/lib/queries/use-ai";
import { useExportSyncBundle, useImportSyncBundle } from "@/lib/queries/use-sync";
import { useOnboarding } from "@/lib/use-onboarding";
import { useIdleLockSetting } from "@/lib/use-idle-lock";
import { setLanguage, SUPPORTED_LANGUAGES, type Language } from "@/i18n";
import type { AiConfig, AiProvider, ReportType, SyncSummary } from "@/lib/types";

const MIN_PASSPHRASE = 8;
const AI_PROVIDERS: AiProvider[] = ["ollama", "openai", "anthropic", "azure", "gemini"];
const DEFAULT_MAX_TOKENS = 1024;
const DEFAULT_API_VERSION = "2024-06-01";

// i18n key for each provider's display label.
const PROVIDER_LABEL_KEY: Record<AiProvider, string> = {
  ollama: "settings.ai.providerOllama",
  openai: "settings.ai.providerOpenai",
  anthropic: "settings.ai.providerAnthropic",
  azure: "settings.ai.providerAzure",
  gemini: "settings.ai.providerGemini",
};

function AppearanceSection() {
  const { t, i18n } = useTranslation();
  const { replay } = useOnboarding();
  const navigate = useNavigate();
  const lang = (SUPPORTED_LANGUAGES as readonly string[]).includes(i18n.language.split("-")[0])
    ? (i18n.language.split("-")[0] as Language)
    : "en";

  const handleShowIntro = () => {
    replay();
    navigate("/");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Palette className="size-4 text-[hsl(var(--accent-brand))]" />
          {t("settings.appearance.title")}
        </CardTitle>
        <CardDescription>{t("settings.appearance.subtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex flex-wrap items-end gap-6">
          <div className="space-y-1.5">
            <Label>{t("settings.appearance.theme")}</Label>
            <div>
              <ThemeToggle />
            </div>
          </div>
          <div className="w-56 space-y-1.5">
            <Label>{t("settings.appearance.language")}</Label>
            <Select value={lang} onValueChange={(v) => setLanguage(v as Language)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SUPPORTED_LANGUAGES.map((l) => (
                  <SelectItem key={l} value={l}>
                    {t(`language.${l}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <Separator />

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium">{t("settings.appearance.showIntro")}</p>
            <p className="text-sm text-muted-foreground">
              {t("settings.appearance.showIntroHint")}
            </p>
          </div>
          <Button variant="outline" onClick={handleShowIntro}>
            {t("settings.appearance.showIntroCta")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function AiSection() {
  const { t } = useTranslation();
  const { data: config } = useAiConfig();
  const saveAi = useSaveAiConfig();
  const testAi = useTestAiConnection();
  const listModels = useAiModels();

  const [draft, setDraft] = useState<AiConfig>({
    enabled: false,
    provider: "ollama",
    base_url: "",
    model: "",
    max_tokens: DEFAULT_MAX_TOKENS,
  });
  const [apiKey, setApiKey] = useState("");
  // Track whether the backend already holds a key so we can hint accordingly.
  const [hasKey, setHasKey] = useState(false);
  // Models fetched on demand from the provider; empty until the user fetches.
  const [models, setModels] = useState<string[]>([]);

  // Hydrate the editable draft from the persisted config once it loads.
  useEffect(() => {
    if (config) {
      setDraft({
        enabled: config.enabled,
        provider: config.provider,
        base_url: config.base_url,
        model: config.model,
        max_tokens: config.max_tokens ?? DEFAULT_MAX_TOKENS,
        api_version: config.api_version,
      });
      setHasKey(config.has_key);
    }
  }, [config]);

  // Ollama runs locally without a key. Every other provider is a cloud service.
  const cloudProvider = draft.provider !== "ollama";
  const isAzure = draft.provider === "azure";
  // The API key is optional for OpenAI-compatible servers (some local/self-hosted
  // gateways are keyless); it stays required for the true cloud providers.
  const keyOptional = draft.provider === "openai";

  const handleFetchModels = () => {
    listModels.mutate(undefined, {
      onSuccess: (ids) => {
        setModels(ids);
        if (ids.length === 0) toast.info(t("settings.ai.fetchModelsEmpty"));
      },
      onError: (err) => {
        setModels([]);
        toast.error(errorMessage(err, "settings.ai.fetchModelsError"));
      },
    });
  };

  const persist = (next: AiConfig, keyArg?: string | null) =>
    saveAi.mutate(
      { config: next, apiKey: keyArg },
      {
        onSuccess: () => {
          setApiKey("");
          if (keyArg) setHasKey(true);
          toast.success(t("settings.ai.saveSuccess"));
        },
        onError: (err) => toast.error(errorMessage(err, "settings.ai.saveError")),
      },
    );

  const handleSave = () => {
    // Only send the key when the field is non-empty; empty means "keep existing".
    persist(draft, apiKey ? apiKey : undefined);
  };

  const handleToggle = (enabled: boolean) => {
    const next = { ...draft, enabled };
    setDraft(next);
    // Persist the toggle immediately so AI affordances appear/disappear at once.
    persist(next, apiKey ? apiKey : undefined);
  };

  const handleTest = () => {
    testAi.mutate(undefined, {
      onSuccess: (msg) => toast.success(msg),
      onError: (err) => toast.error(errorMessage(err, "settings.ai.testError")),
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Sparkles className="size-4 text-[hsl(var(--accent-brand))]" />
          {t("settings.ai.title")}
        </CardTitle>
        <CardDescription>{t("settings.ai.subtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium">{t("settings.ai.enabled")}</p>
            <p className="text-sm text-muted-foreground">{t("settings.ai.enabledHint")}</p>
          </div>
          <Switch
            checked={draft.enabled}
            onCheckedChange={handleToggle}
            aria-label={t("settings.ai.enabled")}
          />
        </div>

        <Separator />

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label>{t("settings.ai.provider")}</Label>
            <Select
              value={draft.provider}
              onValueChange={(v) =>
                setDraft((d) => {
                  const provider = v as AiProvider;
                  return {
                    ...d,
                    provider,
                    // Default the Azure API version when first selecting Azure.
                    api_version:
                      provider === "azure"
                        ? (d.api_version ?? DEFAULT_API_VERSION)
                        : d.api_version,
                  };
                })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AI_PROVIDERS.map((p) => (
                  <SelectItem key={p} value={p}>
                    {t(PROVIDER_LABEL_KEY[p])}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ai-model">{t("settings.ai.model")}</Label>
            <div className="flex gap-2">
              {models.length > 0 ? (
                <Select
                  value={draft.model}
                  onValueChange={(v) => setDraft((d) => ({ ...d, model: v }))}
                >
                  <SelectTrigger id="ai-model" className="font-mono text-xs">
                    <SelectValue placeholder={t("settings.ai.modelPlaceholder")} />
                  </SelectTrigger>
                  <SelectContent>
                    {models.map((m) => (
                      <SelectItem key={m} value={m} className="font-mono text-xs">
                        {m}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  id="ai-model"
                  value={draft.model}
                  onChange={(e) => setDraft((d) => ({ ...d, model: e.target.value }))}
                  placeholder={t("settings.ai.modelPlaceholder")}
                  className="font-mono text-xs"
                />
              )}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleFetchModels}
                disabled={listModels.isPending}
                title={t("settings.ai.fetchModels")}
              >
                <ListPlus />
                <span className="sr-only sm:not-sr-only">
                  {listModels.isPending
                    ? t("settings.ai.fetchingModels")
                    : t("settings.ai.fetchModels")}
                </span>
              </Button>
            </div>
            {models.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {t("settings.ai.fetchModelsFallbackHint")}
              </p>
            )}
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="ai-base-url">{t("settings.ai.baseUrl")}</Label>
            <Input
              id="ai-base-url"
              value={draft.base_url}
              onChange={(e) => setDraft((d) => ({ ...d, base_url: e.target.value }))}
              placeholder={t("settings.ai.baseUrlPlaceholder")}
              className="font-mono text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ai-max-tokens">{t("settings.ai.maxTokens")}</Label>
            <Input
              id="ai-max-tokens"
              type="number"
              min={1}
              value={draft.max_tokens}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  max_tokens: Number(e.target.value) || DEFAULT_MAX_TOKENS,
                }))
              }
              placeholder={String(DEFAULT_MAX_TOKENS)}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">{t("settings.ai.maxTokensHint")}</p>
          </div>
          {isAzure && (
            <div className="space-y-1.5">
              <Label htmlFor="ai-api-version">{t("settings.ai.apiVersion")}</Label>
              <Input
                id="ai-api-version"
                value={draft.api_version ?? ""}
                onChange={(e) => setDraft((d) => ({ ...d, api_version: e.target.value }))}
                placeholder={DEFAULT_API_VERSION}
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">{t("settings.ai.apiVersionHint")}</p>
            </div>
          )}
          {cloudProvider && (
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="ai-key">
                {keyOptional ? t("settings.ai.apiKeyOptional") : t("settings.ai.apiKey")}
              </Label>
              <Input
                id="ai-key"
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  hasKey
                    ? t("settings.ai.apiKeyKeepPlaceholder")
                    : t("settings.ai.apiKeyPlaceholder")
                }
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">{t("settings.ai.apiKeyHint")}</p>
            </div>
          )}
        </div>

        {cloudProvider ? (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-md border border-[hsl(var(--sev-high))] bg-[hsl(var(--sev-high)/0.1)] p-3"
          >
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-[hsl(var(--sev-high))]" />
            <div className="space-y-1 text-xs">
              <p className="font-medium text-[hsl(var(--sev-high))]">
                {t("settings.ai.cloudWarningTitle")}
              </p>
              <p className="text-muted-foreground">{t("settings.ai.cloudWarningBody")}</p>
              <p className="text-muted-foreground">{t("settings.ai.cloudWarningLocalHint")}</p>
            </div>
          </div>
        ) : (
          <div
            className="flex items-start gap-3 rounded-md border border-[hsl(var(--sev-low))] bg-[hsl(var(--sev-low)/0.1)] p-3"
          >
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[hsl(var(--sev-low))]" />
            <p className="text-xs text-muted-foreground">{t("settings.ai.localNote")}</p>
          </div>
        )}

        <div className="flex items-center gap-2">
          <Button variant="brand" onClick={handleSave} disabled={saveAi.isPending}>
            <Save />
            {saveAi.isPending ? t("common.saving") : t("common.save")}
          </Button>
          <Button variant="outline" onClick={handleTest} disabled={testAi.isPending}>
            <Plug />
            {testAi.isPending ? t("settings.ai.testing") : t("settings.ai.test")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

const IDLE_LOCK_OPTIONS = [0, 1, 5, 15, 30, 60] as const;

function SecuritySection() {
  const { t } = useTranslation();
  const [idleMinutes, setIdleMinutes] = useIdleLockSetting();
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
      toast.error(errorMessage(err, "settings.security.changeError"));
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
      toast.error(errorMessage(err, "settings.security.backupError"));
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

        <Separator />

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium">{t("settings.security.idleLockTitle")}</p>
            <p className="text-sm text-muted-foreground">
              {t("settings.security.idleLockHint")}
            </p>
          </div>
          <div className="w-44 space-y-1.5">
            <Label htmlFor="idle-lock">{t("settings.security.idleLockMinutes")}</Label>
            <Select
              value={String(idleMinutes)}
              onValueChange={(v) => setIdleMinutes(Number(v))}
            >
              <SelectTrigger id="idle-lock">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {IDLE_LOCK_OPTIONS.map((m) => (
                  <SelectItem key={m} value={String(m)}>
                    {m === 0
                      ? t("settings.security.idleLockOff")
                      : t("settings.security.idleLockUnit", { count: m })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Passphrase prompt used by the sync export/import flows. When `confirm` is
 * true it requires a matching second field (export); otherwise a single field
 * (import). Validation is client-side; the resolved passphrase is handed back
 * via `onSubmit`.
 */
function PassphraseDialog({
  open: isOpen,
  onOpenChange,
  description,
  confirm,
  pending,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  description: string;
  confirm: boolean;
  pending: boolean;
  onSubmit: (passphrase: string) => void;
}) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState("");
  const [confirmValue, setConfirmValue] = useState("");

  // Reset the fields whenever the dialog opens so passphrases never linger.
  useEffect(() => {
    if (isOpen) {
      setPassphrase("");
      setConfirmValue("");
    }
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase) {
      toast.error(t("settings.sync.passphraseEmpty"));
      return;
    }
    if (confirm && passphrase !== confirmValue) {
      toast.error(t("settings.sync.passphraseMismatch"));
      return;
    }
    onSubmit(passphrase);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t("settings.sync.passphraseTitle")}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="sync-pass">{t("settings.sync.passphrase")}</Label>
            <Input
              id="sync-pass"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="off"
              autoFocus
              required
            />
          </div>
          {confirm && (
            <div className="space-y-1.5">
              <Label htmlFor="sync-pass-confirm">{t("settings.sync.passphraseConfirm")}</Label>
              <Input
                id="sync-pass-confirm"
                type="password"
                value={confirmValue}
                onChange={(e) => setConfirmValue(e.target.value)}
                autoComplete="off"
                required
              />
            </div>
          )}
          <DialogFooter>
            <Button type="submit" variant="brand" disabled={pending}>
              {pending ? t("common.saving") : t("settings.sync.continue")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function todayStamp() {
  return new Date().toISOString().slice(0, 10);
}

function SyncSection() {
  const { t } = useTranslation();
  const exportBundle = useExportSyncBundle();
  const importBundle = useImportSyncBundle();

  // Track which flow the passphrase dialog is serving, plus the file path the
  // user already picked for that flow.
  const [mode, setMode] = useState<"export" | "import" | null>(null);
  const [path, setPath] = useState<string | null>(null);

  const summaryToast = (s: SyncSummary) => {
    const reports = t("settings.sync.summaryReports", {
      added: s.reports_added,
      updated: s.reports_updated,
    });
    const findings = t("settings.sync.summaryFindings", {
      added: s.findings_added,
      updated: s.findings_updated,
    });
    const kb = t("settings.sync.summaryKb", {
      added: s.kb_added,
      updated: s.kb_updated,
    });
    const images = t("settings.sync.summaryImages", { count: s.images_added });
    toast.success(t("settings.sync.importSuccess", { reports, findings, kb, images }));
  };

  const handleExportClick = async () => {
    const dest = await save({
      defaultPath: `pwn2report-sync-${todayStamp()}.p2r`,
      filters: [{ name: t("settings.sync.bundleFile"), extensions: ["p2r"] }],
    });
    if (!dest) return;
    setPath(dest);
    setMode("export");
  };

  const handleImportClick = async () => {
    const src = await open({
      multiple: false,
      directory: false,
      filters: [{ name: t("settings.sync.bundleFile"), extensions: ["p2r"] }],
    });
    if (!src || typeof src !== "string") return;
    setPath(src);
    setMode("import");
  };

  const handlePassphrase = (passphrase: string) => {
    if (!path) return;
    if (mode === "export") {
      exportBundle.mutate(
        { passphrase, destPath: path },
        {
          onSuccess: () => {
            setMode(null);
            toast.success(t("settings.sync.exportSuccess"));
          },
          onError: (err) =>
            toast.error(errorMessage(err, "settings.sync.exportError")),
        },
      );
    } else if (mode === "import") {
      importBundle.mutate(
        { passphrase, srcPath: path },
        {
          onSuccess: (summary) => {
            setMode(null);
            summaryToast(summary);
          },
          onError: (err) =>
            toast.error(errorMessage(err, "settings.sync.importError")),
        },
      );
    }
  };

  const pending = exportBundle.isPending || importBundle.isPending;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <RefreshCw className="size-4 text-[hsl(var(--accent-brand))]" />
          {t("settings.sync.title")}
        </CardTitle>
        <CardDescription>{t("settings.sync.subtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <p className="text-sm text-muted-foreground">{t("settings.sync.description")}</p>

        <Separator />

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium">{t("settings.sync.exportTitle")}</p>
            <p className="text-sm text-muted-foreground">{t("settings.sync.exportHint")}</p>
          </div>
          <Button variant="outline" onClick={handleExportClick} disabled={pending}>
            <Upload />
            {exportBundle.isPending ? t("settings.sync.exporting") : t("settings.sync.exportCta")}
          </Button>
        </div>

        <Separator />

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium">{t("settings.sync.importTitle")}</p>
            <p className="text-sm text-muted-foreground">{t("settings.sync.importHint")}</p>
          </div>
          <Button variant="outline" onClick={handleImportClick} disabled={pending}>
            <Download />
            {importBundle.isPending ? t("settings.sync.importing") : t("settings.sync.importCta")}
          </Button>
        </div>
      </CardContent>

      <PassphraseDialog
        open={mode !== null}
        onOpenChange={(o) => {
          if (!o && !pending) setMode(null);
        }}
        description={
          mode === "export"
            ? t("settings.sync.passphraseExportDescription")
            : t("settings.sync.passphraseImportDescription")
        }
        confirm={mode === "export"}
        pending={pending}
        onSubmit={handlePassphrase}
      />
    </Card>
  );
}

function TemplatesSection() {
  const { t } = useTranslation();
  const { data: templates, isLoading } = useTemplates();
  const [selected, setSelected] = useState<ReportType | undefined>(undefined);
  const { data: source } = useTemplate(selected);
  const [draft, setDraft] = useState("");
  const [confirmReset, setConfirmReset] = useState(false);
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
        onError: (err) => toast.error(errorMessage(err, "settings.templates.saveError")),
      },
    );
  };

  const handleReset = () => {
    if (!selected) return;
    setConfirmReset(true);
  };

  const confirmResetTemplate = () => {
    setConfirmReset(false);
    if (!selected) return;
    resetTemplate.mutate(selected, {
      onSuccess: () => toast.success(t("settings.templates.resetSuccess")),
      onError: (err) => toast.error(errorMessage(err, "settings.templates.resetError")),
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

      <ConfirmDialog
        open={confirmReset}
        onOpenChange={setConfirmReset}
        title={t("settings.templates.resetTitle")}
        description={t("settings.templates.resetConfirm")}
        itemName={selected ? t(`reportType.${selected}`) : undefined}
        confirmLabel={t("settings.templates.resetCta")}
        onConfirm={confirmResetTemplate}
      />
    </Card>
  );
}

const SETTINGS_SECTIONS = [
  { id: "appearance", Component: AppearanceSection },
  { id: "ai", Component: AiSection },
  { id: "security", Component: SecuritySection },
  { id: "sync", Component: SyncSection },
  { id: "templates", Component: TemplatesSection },
] as const;

export function Settings() {
  const { t } = useTranslation();
  const [active, setActive] = useState<string>(SETTINGS_SECTIONS[0].id);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Highlight the section currently in view as the user scrolls.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible) setActive(visible.target.id);
      },
      { rootMargin: "-20% 0px -70% 0px", threshold: [0, 0.25, 0.5, 1] },
    );
    const container = containerRef.current;
    container?.querySelectorAll("[data-settings-section]").forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  const scrollTo = (sectionId: string) => {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      setActive(sectionId);
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">{t("settings.title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("settings.subtitle")}</p>
      </header>

      <div className="gap-8 md:flex">
        <nav
          aria-label={t("settings.sectionNav")}
          className="mb-6 md:sticky md:top-20 md:mb-0 md:h-fit md:w-48 md:shrink-0"
        >
          <ul className="flex flex-wrap gap-1 md:flex-col">
            {SETTINGS_SECTIONS.map(({ id }) => (
              <li key={id}>
                <button
                  type="button"
                  onClick={() => scrollTo(id)}
                  aria-current={active === id ? "true" : undefined}
                  className={`w-full rounded-md px-3 py-1.5 text-left text-sm font-medium transition-colors ${
                    active === id
                      ? "bg-accent text-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground"
                  }`}
                >
                  {t(`settings.sections.${id}`)}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <div ref={containerRef} className="min-w-0 flex-1 space-y-6">
          {SETTINGS_SECTIONS.map(({ id, Component }) => (
            <section key={id} id={id} data-settings-section className="scroll-mt-20">
              <Component />
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
