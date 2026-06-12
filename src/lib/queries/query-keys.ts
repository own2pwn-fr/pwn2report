export const queryKeys = {
  vault: ["vault"] as const,
  reports: ["reports"] as const,
  report: (id: string) => ["reports", id] as const,
  findings: (reportId: string) => ["findings", reportId] as const,
};
