//! Shared test fixtures: minimal `Report` / `Finding` builders used by the
//! renderer unit tests. Test-only (gated behind `#[cfg(test)]`).

use crate::models::{
    Confidence, Evidence, Finding, FindingDescription, FindingKind, FindingRemediation, Report,
    ReportType, Severity, StructuredPoc, TriageStatus,
};

/// A representative report with all narrative sections populated.
pub fn sample_report() -> Report {
    Report {
        id: "r1".into(),
        title: "Test Report".into(),
        client: "ACME Corp".into(),
        report_type: ReportType::WebPentest,
        status: "draft".into(),
        exec_summary: "An overview of the assessment.".into(),
        scope: "https://app.example.com".into(),
        methodology: "OWASP WSTG.".into(),
        created_at: "2026-06-12T00:00:00Z".into(),
        updated_at: "2026-06-12T12:00:00Z".into(),
        deleted_at: None,
    }
}

/// A representative finding exercising evidence, PoC, remediation and metadata.
pub fn sample_finding() -> Finding {
    Finding {
        id: "f1".into(),
        report_id: "r1".into(),
        sort_order: 0,
        title: "SQL Injection".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        kind: FindingKind::Manual,
        cwe: Some("CWE-89".into()),
        cve: None,
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
        cvss_score: Some(8.6),
        triage_status: TriageStatus::Open,
        triage_note: None,
        description: FindingDescription {
            summary: "User input reaches a SQL query unsanitized.".into(),
            root_cause: "String concatenation in the data layer.".into(),
            attack_vector: "Crafted query parameter.".into(),
            business_impact: "Full database disclosure.".into(),
            technical_details: "The `id` param is concatenated.".into(),
        },
        remediation: FindingRemediation {
            fix: "Use parameterized queries.".into(),
            code_patch: Some("cursor.execute(\"... WHERE id = ?\", (id,))".into()),
            references: vec!["https://owasp.org/sqli".into()],
        },
        evidence: Some(Evidence {
            file: Some("app/db.py".into()),
            start_line: Some(42),
            end_line: Some(45),
            snippet: Some("SELECT * FROM users WHERE id = ' + id".into()),
        }),
        poc: Some(StructuredPoc {
            scenario: "Attacker injects a UNION select.".into(),
            exploitation_steps: vec!["Intercept request".into(), "Inject payload".into()],
            payload: Some("1' OR '1'='1".into()),
        }),
        refs: vec!["https://example.com/ref".into()],
        tags: vec!["injection".into(), "owasp-a03".into()],
        created_at: "2026-06-12T00:00:00Z".into(),
        updated_at: "2026-06-12T12:00:00Z".into(),
        deleted_at: None,
    }
}
