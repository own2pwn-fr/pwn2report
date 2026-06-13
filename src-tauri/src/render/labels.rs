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

    // Findings-summary table column headers (the per-finding overview table).
    /// "#" column header (finding index).
    pub number: &'static str,
    /// "Title" column header.
    pub title: &'static str,
    /// "Score" column header (CVSS numeric score).
    pub score: &'static str,

    // CVSS decoded-vector metric labels. Metric NAMES (left column of the grid).
    pub cvss_attack_vector: &'static str,
    pub cvss_attack_complexity: &'static str,
    pub cvss_attack_requirements: &'static str,
    pub cvss_privileges_required: &'static str,
    pub cvss_user_interaction: &'static str,
    pub cvss_scope: &'static str,
    pub cvss_confidentiality: &'static str,
    pub cvss_integrity: &'static str,
    pub cvss_availability: &'static str,
    // CVSS metric VALUES (right column of the grid).
    pub cvss_network: &'static str,
    pub cvss_adjacent: &'static str,
    pub cvss_local: &'static str,
    pub cvss_physical: &'static str,
    pub cvss_low: &'static str,
    pub cvss_high: &'static str,
    pub cvss_none: &'static str,
    pub cvss_required: &'static str,
    pub cvss_passive: &'static str,
    pub cvss_active: &'static str,
    pub cvss_present: &'static str,
    pub cvss_unchanged: &'static str,
    pub cvss_changed: &'static str,

    // Aggregate report layer: scope table.
    /// Structured-scope section heading.
    pub scope_table: &'static str,
    pub in_scope: &'static str,
    pub out_of_scope: &'static str,
    /// Per-finding "Affected assets" label.
    pub affected_assets: &'static str,

    // Engagement metadata (title page).
    pub authors: &'static str,
    pub reviewer: &'static str,
    pub engagement_period: &'static str,
    pub reference: &'static str,
    pub confidentiality: &'static str,

    // Asset kinds (host / ip / url / domain / credential / other).
    pub asset_host: &'static str,
    pub asset_ip: &'static str,
    pub asset_url: &'static str,
    pub asset_domain: &'static str,
    pub asset_credential: &'static str,
    pub asset_other: &'static str,

    // Retest workflow (schema v7).
    /// "Retest" badge/section label.
    pub retest: &'static str,
    pub retest_not_retested: &'static str,
    pub retest_fixed: &'static str,
    pub retest_partially_fixed: &'static str,
    pub retest_not_fixed: &'static str,
    pub retest_risk_accepted: &'static str,

    // Compliance mappings + custom fields (schema v7).
    /// "Mappings" / "References to frameworks" section heading.
    pub mappings: &'static str,
    /// "Custom fields" section heading.
    pub custom_fields: &'static str,
    /// "Field" column header (custom-fields table).
    pub field: &'static str,
    /// "Value" column header (custom-fields table).
    pub value: &'static str,

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

    number: "#",
    title: "Title",
    score: "Score",

    cvss_attack_vector: "Attack vector",
    cvss_attack_complexity: "Attack complexity",
    cvss_attack_requirements: "Attack requirements",
    cvss_privileges_required: "Privileges required",
    cvss_user_interaction: "User interaction",
    cvss_scope: "Scope",
    cvss_confidentiality: "Confidentiality",
    cvss_integrity: "Integrity",
    cvss_availability: "Availability",
    cvss_network: "Network",
    cvss_adjacent: "Adjacent",
    cvss_local: "Local",
    cvss_physical: "Physical",
    cvss_low: "Low",
    cvss_high: "High",
    cvss_none: "None",
    cvss_required: "Required",
    cvss_passive: "Passive",
    cvss_active: "Active",
    cvss_present: "Present",
    cvss_unchanged: "Unchanged",
    cvss_changed: "Changed",

    scope_table: "Scope",
    in_scope: "In scope",
    out_of_scope: "Out of scope",
    affected_assets: "Affected assets",

    authors: "Authors",
    reviewer: "Reviewer",
    engagement_period: "Engagement period",
    reference: "Reference",
    confidentiality: "Confidentiality",

    asset_host: "Host",
    asset_ip: "IP",
    asset_url: "URL",
    asset_domain: "Domain",
    asset_credential: "Credential",
    asset_other: "Other",

    retest: "Retest",
    retest_not_retested: "Not retested",
    retest_fixed: "Fixed",
    retest_partially_fixed: "Partially fixed",
    retest_not_fixed: "Not fixed",
    retest_risk_accepted: "Risk accepted",

    mappings: "References to frameworks",
    custom_fields: "Custom fields",
    field: "Field",
    value: "Value",

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

    number: "N°",
    title: "Titre",
    score: "Score",

    cvss_attack_vector: "Vecteur d'attaque",
    cvss_attack_complexity: "Complexité de l'attaque",
    cvss_attack_requirements: "Prérequis de l'attaque",
    cvss_privileges_required: "Privilèges requis",
    cvss_user_interaction: "Interaction utilisateur",
    cvss_scope: "Portée",
    cvss_confidentiality: "Confidentialité",
    cvss_integrity: "Intégrité",
    cvss_availability: "Disponibilité",
    cvss_network: "Réseau",
    cvss_adjacent: "Adjacent",
    cvss_local: "Local",
    cvss_physical: "Physique",
    cvss_low: "Faible",
    cvss_high: "Élevée",
    cvss_none: "Aucun",
    cvss_required: "Requise",
    cvss_passive: "Passive",
    cvss_active: "Active",
    cvss_present: "Présent",
    cvss_unchanged: "Inchangée",
    cvss_changed: "Modifiée",

    scope_table: "Périmètre",
    in_scope: "Dans le périmètre",
    out_of_scope: "Hors périmètre",
    affected_assets: "Actifs affectés",

    authors: "Auteurs",
    reviewer: "Relecteur",
    engagement_period: "Période d'engagement",
    reference: "Référence",
    confidentiality: "Confidentialité",

    asset_host: "Hôte",
    asset_ip: "IP",
    asset_url: "URL",
    asset_domain: "Domaine",
    asset_credential: "Identifiant",
    asset_other: "Autre",

    retest: "Contre-test",
    retest_not_retested: "Non recontrôlé",
    retest_fixed: "Corrigé",
    retest_partially_fixed: "Partiellement corrigé",
    retest_not_fixed: "Non corrigé",
    retest_risk_accepted: "Risque accepté",

    mappings: "Références aux référentiels",
    custom_fields: "Champs personnalisés",
    field: "Champ",
    value: "Valeur",

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
