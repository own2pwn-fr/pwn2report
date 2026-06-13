//! Localized label dictionary for report exports.
//!
//! Every user-facing string the renderers (Markdown / HTML / DOCX) and the
//! Typst themes used to hardcode in English lives here, so a report can be
//! exported in the language carried by its `language` field. The renderers read
//! `doc.labels.*` instead of literals; the Typst path also injects the table
//! (and `doc.lang`) into the template so the themes index `doc.labels.<key>`
//! and `#set text(lang: doc.lang)` follows the report language.
//!
//! Adding a language = add a `match` arm to [`Labels::for_lang`] returning a
//! fully-populated table (no partial tables — keep every field translated).
//! Unknown codes fall back to English.

use derive_typst_intoval::{IntoDict, IntoValue};
use typst::foundations::{Dict, IntoValue as _};

/// Every localizable string used by the renderers + themes.
///
/// Plain `&'static str` fields (the tables are compile-time constants).
/// Derives `IntoDict`/`IntoValue` so the Typst path can inject the whole struct
/// as a dict the themes index (`doc.labels.executive_summary`, …).
#[derive(Debug, Clone, Copy, IntoValue, IntoDict)]
pub struct Labels {
    // Report-type display names (replace the old `report_type_label`).
    pub report_type_web_pentest: &'static str,
    pub report_type_code_audit: &'static str,
    pub report_type_red_team: &'static str,

    // Section titles. The neutral variants are used by md/html/docx (uniform
    // layout); the themes pick the type-specific variants where they differ.
    pub executive_summary: &'static str,
    /// Red-team variant of the executive summary heading.
    pub engagement_summary: &'static str,
    pub findings_overview: &'static str,
    /// Red-team variant of the findings-overview heading.
    pub impact_overview: &'static str,
    pub scope: &'static str,
    /// Red-team variant of the scope heading.
    pub rules_of_engagement: &'static str,
    pub methodology: &'static str,
    /// Red-team variant of the methodology heading.
    pub approach: &'static str,
    pub detailed_findings: &'static str,
    /// Red-team variant of the detailed-findings heading.
    pub attack_narratives: &'static str,
    pub table_of_contents: &'static str,

    // Title-page / metadata labels.
    pub client: &'static str,
    pub report_type: &'static str,
    pub status: &'static str,
    pub date: &'static str,

    // Severity-summary table.
    pub severity: &'static str,
    pub count: &'static str,
    pub total: &'static str,
    pub critical: &'static str,
    pub high: &'static str,
    pub medium: &'static str,
    pub low: &'static str,
    pub info: &'static str,

    // Per-finding facet/section labels.
    pub summary: &'static str,
    pub root_cause: &'static str,
    pub attack_vector: &'static str,
    pub business_impact: &'static str,
    pub technical_details: &'static str,
    pub remediation: &'static str,
    /// Red-team variant of the remediation label.
    pub recommendation: &'static str,
    pub proof_of_concept: &'static str,
    pub references: &'static str,
    pub evidence: &'static str,
    pub screenshots: &'static str,
    pub confidence: &'static str,
    pub cvss: &'static str,
    /// Code-audit "Weakness:" prefix (the CWE callout).
    pub weakness: &'static str,
    /// Code-audit "Vulnerable code" snippet label.
    pub vulnerable_code: &'static str,
    /// Code-audit "Suggested patch" label.
    pub suggested_patch: &'static str,
    /// Red-team "Scenario" facet label.
    pub scenario: &'static str,
    /// Red-team "Exploitation steps" label.
    pub exploitation_steps: &'static str,
    /// Red-team "Payload" label.
    pub payload: &'static str,
    pub tags: &'static str,

    // Fallbacks.
    pub no_findings: &'static str,
}

/// English label table (also the fallback for unknown language codes).
const EN: Labels = Labels {
    report_type_web_pentest: "Web Penetration Test",
    report_type_code_audit: "Code Audit",
    report_type_red_team: "Red Team Engagement",

    executive_summary: "Executive Summary",
    engagement_summary: "Engagement Summary",
    findings_overview: "Findings Overview",
    impact_overview: "Impact Overview",
    scope: "Scope",
    rules_of_engagement: "Rules of Engagement",
    methodology: "Methodology",
    approach: "Approach",
    detailed_findings: "Detailed Findings",
    attack_narratives: "Attack Narratives",
    table_of_contents: "Table of Contents",

    client: "Client",
    report_type: "Type",
    status: "Status",
    date: "Date",

    severity: "Severity",
    count: "Count",
    total: "Total",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",

    summary: "Summary",
    root_cause: "Root cause",
    attack_vector: "Attack vector",
    business_impact: "Business impact",
    technical_details: "Technical details",
    remediation: "Remediation",
    recommendation: "Recommendation",
    proof_of_concept: "Proof of Concept",
    references: "References",
    evidence: "Evidence",
    screenshots: "Screenshots",
    confidence: "Confidence",
    cvss: "CVSS",
    weakness: "Weakness",
    vulnerable_code: "Vulnerable code",
    suggested_patch: "Suggested patch",
    scenario: "Scenario",
    exploitation_steps: "Exploitation steps",
    payload: "Payload",
    tags: "Tags",

    no_findings: "No findings recorded for this report.",
};

/// French label table.
const FR: Labels = Labels {
    report_type_web_pentest: "Test d'intrusion web",
    report_type_code_audit: "Audit de code",
    report_type_red_team: "Engagement Red Team",

    executive_summary: "Synthèse",
    engagement_summary: "Synthèse de l'engagement",
    findings_overview: "Vue d'ensemble des vulnérabilités",
    impact_overview: "Vue d'ensemble des impacts",
    scope: "Périmètre",
    rules_of_engagement: "Règles d'engagement",
    methodology: "Méthodologie",
    approach: "Approche",
    detailed_findings: "Vulnérabilités détaillées",
    attack_narratives: "Récits d'attaque",
    table_of_contents: "Table des matières",

    client: "Client",
    report_type: "Type",
    status: "Statut",
    date: "Date",

    severity: "Sévérité",
    count: "Nombre",
    total: "Total",
    critical: "Critique",
    high: "Élevée",
    medium: "Moyenne",
    low: "Faible",
    info: "Info",

    summary: "Résumé",
    root_cause: "Cause racine",
    attack_vector: "Vecteur d'attaque",
    business_impact: "Impact métier",
    technical_details: "Détails techniques",
    remediation: "Remédiation",
    recommendation: "Recommandation",
    proof_of_concept: "Preuve de concept",
    references: "Références",
    evidence: "Preuve",
    screenshots: "Captures d'écran",
    confidence: "Confiance",
    cvss: "CVSS",
    weakness: "Faiblesse",
    vulnerable_code: "Code vulnérable",
    suggested_patch: "Correctif suggéré",
    scenario: "Scénario",
    exploitation_steps: "Étapes d'exploitation",
    payload: "Charge utile",
    tags: "Étiquettes",

    no_findings: "Aucune vulnérabilité enregistrée pour ce rapport.",
};

impl Labels {
    /// Resolve the label table for a language code (RFC-ish, e.g. `"en"`,
    /// `"fr"`, `"fr-FR"`). Only the primary subtag is matched; unknown codes
    /// fall back to English.
    pub fn for_lang(code: &str) -> Labels {
        let primary = code
            .split(['-', '_'])
            .next()
            .unwrap_or(code)
            .to_ascii_lowercase();
        match primary.as_str() {
            "fr" => FR,
            _ => EN,
        }
    }
}

/// Required by `compile_with_input` indirectly (the derive emits `into_dict`).
impl From<Labels> for Dict {
    fn from(v: Labels) -> Self {
        v.into_dict()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_lang_falls_back_to_english() {
        assert_eq!(
            Labels::for_lang("xx").executive_summary,
            "Executive Summary"
        );
        assert_eq!(Labels::for_lang("").total, "Total");
    }

    #[test]
    fn french_table_is_selected_and_translated() {
        let fr = Labels::for_lang("fr");
        assert_eq!(fr.executive_summary, "Synthèse");
        assert_eq!(
            fr.no_findings,
            "Aucune vulnérabilité enregistrée pour ce rapport."
        );
    }

    #[test]
    fn region_subtag_is_ignored() {
        assert_eq!(Labels::for_lang("fr-FR").scope, "Périmètre");
        assert_eq!(Labels::for_lang("en-US").scope, "Scope");
    }
}
