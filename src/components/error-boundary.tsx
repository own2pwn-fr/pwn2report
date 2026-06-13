import React from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangle, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Styled fallback shown when a render error is caught. */
function ErrorFallback({ error, onReload }: { error: Error | null; onReload: () => void }) {
  const { t } = useTranslation();
  return (
    <div
      role="alert"
      className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center"
    >
      <div
        className="flex size-14 items-center justify-center rounded-full"
        style={{ backgroundColor: "hsl(var(--sev-high) / 0.12)" }}
      >
        <AlertTriangle className="size-6 text-[hsl(var(--sev-high))]" />
      </div>
      <div className="space-y-1.5">
        <h1 className="text-lg font-semibold">{t("appError.title")}</h1>
        <p className="max-w-sm text-sm text-muted-foreground">{t("appError.body")}</p>
      </div>
      {error?.message && (
        <pre className="max-w-md overflow-x-auto rounded-md border bg-muted/40 p-3 text-left font-mono text-xs text-muted-foreground">
          {error.message}
        </pre>
      )}
      <Button variant="brand" onClick={onReload}>
        <RotateCcw />
        {t("appError.reload")}
      </Button>
    </div>
  );
}

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * App-level error boundary. Catches render/lifecycle errors below it and shows a
 * styled, translatable fallback with a reload action instead of a blank screen.
 */
export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Surface to the console for diagnostics; there is no remote logging here.
    console.error("Uncaught error in render tree:", error, info);
  }

  private handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.error) {
      return <ErrorFallback error={this.state.error} onReload={this.handleReload} />;
    }
    return this.props.children;
  }
}
