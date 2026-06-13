import { useState } from "react";
import { motion } from "motion/react";
import { ShieldCheck, KeyRound, Lock } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ThemeToggle } from "@/components/theme-toggle";
import { LanguageToggle } from "@/components/language-toggle";
import {
  useCreateVault,
  useUnlockVault,
  useUnlockWithKeychain,
  useVaultStatus,
} from "@/lib/queries/use-vault";
import { errorMessage } from "@/lib/ipc";

export function VaultGate() {
  const { t } = useTranslation();
  const { data: status } = useVaultStatus();
  const isCreate = status ? !status.exists : false;

  const createVault = useCreateVault();
  const unlockVault = useUnlockVault();
  const unlockKeychain = useUnlockWithKeychain();

  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pending = createVault.isPending || unlockVault.isPending || unlockKeychain.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (isCreate) {
      if (passphrase.length < 8) {
        setError(t("vault.tooShort"));
        return;
      }
      if (passphrase !== confirm) {
        setError(t("vault.mismatch"));
        return;
      }
      createVault.mutate(
        { passphrase, remember },
        {
          onError: (err) => setError(errorMessage(err)),
        },
      );
    } else {
      unlockVault.mutate(
        { passphrase, remember },
        {
          onError: () => setError(t("vault.wrong")),
        },
      );
    }
  };

  const handleKeychain = () => {
    setError(null);
    unlockKeychain.mutate(undefined, {
      onSuccess: (ok) => {
        if (!ok) setError(t("vault.keychainFailed"));
      },
      onError: (err) => {
        toast.error(errorMessage(err));
        setError(t("vault.keychainFailed"));
      },
    });
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="absolute right-4 top-4 flex items-center gap-1">
        <ThemeToggle />
        <LanguageToggle />
      </div>
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="w-full max-w-md"
      >
        <div className="mb-6 text-center">
          <div
            className="mx-auto mb-4 flex size-12 items-center justify-center rounded-xl"
            style={{ backgroundColor: "hsl(var(--accent-brand) / 0.14)" }}
          >
            <Lock className="size-6 text-accent-brand" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">{t("app.name")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t("app.tagline")}</p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5 text-accent-brand" />
              {isCreate ? t("vault.createTitle") : t("vault.unlockTitle")}
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              {isCreate ? t("vault.createSubtitle") : t("vault.unlockSubtitle")}
            </p>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="passphrase">{t("vault.passphrase")}</Label>
                <Input
                  id="passphrase"
                  type="password"
                  autoFocus
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder={t("vault.passphrasePlaceholder")}
                  autoComplete={isCreate ? "new-password" : "current-password"}
                />
              </div>

              {isCreate && (
                <div className="space-y-1.5">
                  <Label htmlFor="confirm">{t("vault.confirmPassphrase")}</Label>
                  <Input
                    id="confirm"
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder={t("vault.confirmPlaceholder")}
                    autoComplete="new-password"
                  />
                </div>
              )}

              <label className="flex cursor-pointer items-start gap-2.5 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5 size-4 accent-[hsl(var(--accent-brand))]"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                />
                <span>
                  <span className="font-medium">{t("vault.remember")}</span>
                  <span className="block text-xs text-muted-foreground">
                    {t("vault.rememberHint")}
                  </span>
                </span>
              </label>

              {error && (
                <p className="text-sm text-destructive" role="alert">
                  {error}
                </p>
              )}

              <Button
                type="submit"
                variant="brand"
                className="w-full"
                disabled={pending || !passphrase}
              >
                {isCreate
                  ? createVault.isPending
                    ? t("vault.creating")
                    : t("vault.create")
                  : unlockVault.isPending
                    ? t("vault.unlocking")
                    : t("vault.unlock")}
              </Button>

              {!isCreate && status?.keychain_available && (
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  disabled={pending}
                  onClick={handleKeychain}
                >
                  <KeyRound />
                  {t("vault.unlockWithKeychain")}
                </Button>
              )}
            </form>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
