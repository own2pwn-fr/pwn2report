import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useVaultStatus } from "@/lib/queries/use-vault";
import { AppShell } from "@/app/app-shell";
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
  const { showOnboarding, finish } = useOnboarding();

  if (isLoading || !status) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="size-6 animate-spin rounded-full border-2 border-muted border-t-[hsl(var(--accent-brand))]" />
      </div>
    );
  }

  // Vault gate guard: anything other than an unlocked vault forces /vault.
  if (!status.unlocked) {
    if (location.pathname !== "/vault") return <Navigate to="/vault" replace />;
    return <VaultGate />;
  }

  // Unlocked: render the persistent shell with the routed pages inside it.
  // The shell owns its own <AnimatePresence> + page transitions.
  return (
    <>
      <Routes>
        <Route path="/vault" element={<Navigate to="/" replace />} />
        <Route element={<AppShell />}>
          <Route path="/" element={<ReportsList />} />
          <Route path="/kb" element={<KnowledgeBase />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/reports/:id" element={<ReportDetail />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
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
