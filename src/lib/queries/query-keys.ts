export const queryKeys = {
  vault: ["vault"] as const,
  reports: ["reports"] as const,
  report: (id: string) => ["reports", id] as const,
  findings: (reportId: string) => ["findings", reportId] as const,
  kb: ["kb"] as const,
  kbEntry: (id: string) => ["kb", id] as const,
  evidence: (findingId: string) => ["evidence", findingId] as const,
  evidenceBytes: (id: string) => ["evidence", "bytes", id] as const,
};
