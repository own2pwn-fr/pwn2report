// pwn2report — A4 red-team report theme.
//
// Reads its data from `#import sys: inputs` (populated by the Rust render IR in
// render/content_model.rs). Shares the title page / severity-summary table /
// header-footer with the other themes (via lib/common.typ), but each finding
// reads like an ATTACK STORY: the PoC scenario leads, the exploitation steps are
// a numbered narrative, the payload is shown, and severity is still surfaced.
//
// CUSTOM TEMPLATES: bundled default for the `red_team` report type. A user
// override lives at `<app_config_dir>/templates/red_team.typ`. A custom
// template MUST import the shared lib at the stable path below — do NOT change
// it (it is registered in-memory by the renderer under exactly this path):
//   #import "lib/common.typ": ...
//
// Robust to missing optional fields: the IR flattens them to "" / empty arrays.

#import sys: inputs
#import "lib/common.typ": severity-color, severity-label, severity-badge, tag-pill, facet, prose, code-block, accent, make-header, make-footer, title-page, severity-summary-table, severity-distribution-bar, findings-summary-table, finding-heading, finding-meta, evidence-loc, references-block, finding-separator, finding-images, scope-table, affected-assets, retest-badge, mappings-block, custom-fields-table

#let doc = inputs
// Localized label dict injected by the Rust render IR (doc.labels.*).
#let l = doc.labels

// ---------------------------------------------------------------------------
// Page + text defaults
// ---------------------------------------------------------------------------
#set page(
  paper: "a4",
  margin: (x: 2.2cm, y: 2.4cm),
  header: make-header(doc),
  footer: make-footer(),
)
// Typography/hyphenation follows the report language.
#set text(font: "Inter", size: 10.5pt, lang: doc.lang)
#set par(justify: true, leading: 0.62em)
#show heading: set text(fill: accent)
// Real heading numbering so sections + findings are numbered and outlined.
#set heading(numbering: "1.1")
#set figure(numbering: "1")

// ---------------------------------------------------------------------------
// Title page
// ---------------------------------------------------------------------------
#title-page(doc, l)

#pagebreak()

// ---------------------------------------------------------------------------
// Table of contents
// ---------------------------------------------------------------------------
#outline(title: l.table_of_contents, depth: 2)
#pagebreak()

// ---------------------------------------------------------------------------
// Executive summary (the engagement narrative overview)
// ---------------------------------------------------------------------------
#if doc.exec_summary != "" {
  heading(level: 1, l.engagement_summary)
  block(prose(doc.exec_summary))
  v(0.5em)
}

// ---------------------------------------------------------------------------
// Severity summary table + distribution bar
// ---------------------------------------------------------------------------
#heading(level: 1, l.impact_overview)
#severity-distribution-bar(doc.summary)
#severity-summary-table(doc.summary, l)
#v(0.5em)

// ---------------------------------------------------------------------------
// Scope (rules of engagement) & methodology (attack approach)
// ---------------------------------------------------------------------------
#if doc.scope != "" or ("scope_items" in doc and doc.scope_items.len() > 0) {
  heading(level: 1, l.rules_of_engagement)
  if doc.scope != "" { block(prose(doc.scope)) }
  if "scope_items" in doc { scope-table(doc.scope_items, l) }
}
#if doc.methodology != "" {
  heading(level: 1, l.approach)
  block(prose(doc.methodology))
}

// Report-level custom fields.
#if "custom_fields" in doc and doc.custom_fields.len() > 0 {
  heading(level: 1, l.custom_fields)
  custom-fields-table(doc.custom_fields, l)
}

// ---------------------------------------------------------------------------
// Findings — attack-narrative layout
// ---------------------------------------------------------------------------
#if doc.findings.len() > 0 {
  pagebreak()
  heading(level: 1, l.attack_narratives)

  // At-a-glance summary table of all findings before the detailed narratives.
  findings-summary-table(doc.findings, l)
  v(0.6em)

  for (i, f) in doc.findings.enumerate() {
    finding-heading(i + 1, f)
    finding-meta(f, l)

    // Retest status badge (when recorded).
    retest-badge(f, l.retest)

    // Lead with the scenario — the story of the attack.
    if f.has_poc and f.poc_scenario != "" {
      facet(l.scenario, f.poc_scenario)
    } else if f.summary != "" {
      facet(l.scenario, f.summary)
    }

    // Numbered exploitation walk-through.
    if f.has_poc and f.poc_steps.len() > 0 {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, l.exploitation_steps))
      block(spacing: 6pt, enum(..f.poc_steps))
    }

    // Payload used in the exploitation.
    if f.has_poc and f.poc_payload != "" {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, l.payload))
      code-block(f.poc_payload)
    }

    // Supporting context — attack vector and business impact tell the "so what".
    facet(l.attack_vector, f.attack_vector)
    facet(l.business_impact, f.business_impact)
    facet(l.technical_details, f.technical_details)
    facet(l.root_cause, f.root_cause)

    // Affected assets / targets (the finding↔asset link set).
    affected-assets(f, l.affected_assets)

    // Evidence captured during the operation.
    if f.has_evidence {
      let loc = evidence-loc(f)
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, l.evidence))
      if loc != "" {
        block(spacing: 4pt, text(size: 8.5pt, fill: luma(120), font: "JetBrains Mono", loc))
      }
      code-block(f.evidence_snippet)
    }

    // Evidence images (screenshots captured during the operation).
    finding-images(f, l.screenshots)

    // Remediation / hardening recommendations.
    if f.fix != "" or f.code_patch != "" or f.remediation_refs.len() > 0 {
      facet(l.recommendation, f.fix)
      code-block(f.code_patch)
      references-block(f.remediation_refs, l.references)
    }

    // Compliance / framework mappings.
    mappings-block(f, l.mappings)

    // Per-finding custom fields.
    custom-fields-table(f.custom_fields, l)

    // Tags.
    if f.tags.len() > 0 {
      block(spacing: 8pt, f.tags.map(tag-pill).join(h(4pt)))
    }

    finding-separator(i, doc.findings.len())
  }
} else {
  v(1em)
  text(fill: luma(130), style: "italic", l.no_findings)
}
