import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import App from "./App";
import { initTheme } from "@/lib/use-theme";
import "@/i18n";
import "@/app/globals.css";

// Apply the persisted theme before first paint to avoid a flash.
initTheme();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
      <Toaster position="bottom-right" richColors closeButton theme="system" />
    </QueryClientProvider>
  </React.StrictMode>,
);
