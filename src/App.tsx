import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AnimatePresence } from "motion/react";
import { useTranslation } from "react-i18next";
import { useVaultStatus } from "@/lib/queries/use-vault";
import { VaultGate } from "@/app/routes/vault-gate";
import { ReportsList } from "@/app/routes/reports-list";
import { ReportDetail } from "@/app/routes/report-detail";
import { Settings } from "@/app/routes/settings";
import { KnowledgeBase } from "@/app/routes/kb";
import { OnboardingDialog } from "@/components/onboarding/onboarding-dialog";
import { useOnboarding } from "@/lib/use-onboarding";

function GatedRoutes() {
  const location = useLocation();
  const { data: status, isLoading } = useVaultStatus();
  const { t } = useTranslation();
  const { showOnboarding, finish } = useOnboarding();

  if (isLoading || !status) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      </div>
    );
  }

  // Vault gate guard: anything other than an unlocked vault forces /vault.
  if (!status.unlocked) {
    if (location.pathname !== "/vault") return <Navigate to="/vault" replace />;
    return <VaultGate />;
  }

  // Unlocked: keep users out of the vault screen.
  return (
    <>
      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          <Route path="/vault" element={<Navigate to="/" replace />} />
          <Route path="/" element={<ReportsList />} />
          <Route path="/kb" element={<KnowledgeBase />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/reports/:id" element={<ReportDetail />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AnimatePresence>
      <OnboardingDialog open={showOnboarding} onDone={finish} />
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <GatedRoutes />
    </BrowserRouter>
  );
}
