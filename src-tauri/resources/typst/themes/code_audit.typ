// pwn2report — A4 code-audit report theme.
//
// Reads its data from `#import sys: inputs` (populated by the Rust render IR in
// render/content_model.rs). Shares the title page / severity-summary table /
// header-footer with the other themes (via lib/common.typ), but per finding it
// emphasises the SOURCE: file/line location first, the evidence code snippet in
// a JetBrains Mono block, the CWE, and the remediation code patch as a code
// block.
//
// CUSTOM TEMPLATES: bundled default for the `code_audit` report type. A user
// override lives at `<app_config_dir>/templates/code_audit.typ`. A custom
// template MUST import the shared lib at the stable path below — do NOT change
// it (it is registered in-memory by the renderer under exactly this path):
//   #import "lib/common.typ": ...
//
// Robust to missing optional fields: the IR flattens them to "" / empty arrays.

#import sys: inputs
#import "lib/common.typ": severity-color, severity-label, severity-badge, tag-pill, facet, prose, code-block, accent, make-header, make-footer, title-page, severity-summary-table, severity-distribution-bar, findings-summary-table, finding-heading, finding-meta, evidence-loc, references-block, finding-separator, finding-images, scope-table, affected-assets

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

// A prominent location banner ("file:lines"), monospace.
#let location-banner(f) = {
  let loc = evidence-loc(f)
  if loc != "" {
    block(
      width: 100%,
      fill: rgb("#f3f0ff"),
      stroke: 0.5pt + accent,
      inset: 6pt,
      radius: 4pt,
      text(font: "JetBrains Mono", size: 9pt, fill: accent, weight: "bold", loc),
    )
  }
}

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
// Executive summary
// ---------------------------------------------------------------------------
#if doc.exec_summary != "" {
  heading(level: 1, l.executive_summary)
  block(prose(doc.exec_summary))
  v(0.5em)
}

// ---------------------------------------------------------------------------
// Severity summary table + distribution bar
// ---------------------------------------------------------------------------
#heading(level: 1, l.findings_overview)
#severity-distribution-bar(doc.summary)
#severity-summary-table(doc.summary, l)
#v(0.5em)

// ---------------------------------------------------------------------------
// Scope & methodology
// ---------------------------------------------------------------------------
#if doc.scope != "" or ("scope_items" in doc and doc.scope_items.len() > 0) {
  heading(level: 1, l.scope)
  if doc.scope != "" { block(prose(doc.scope)) }
  if "scope_items" in doc { scope-table(doc.scope_items, l) }
}
#if doc.methodology != "" {
  heading(level: 1, l.methodology)
  block(prose(doc.methodology))
}

// ---------------------------------------------------------------------------
// Findings — source-centric layout
// ---------------------------------------------------------------------------
#if doc.findings.len() > 0 {
  pagebreak()
  heading(level: 1, l.detailed_findings)

  // At-a-glance summary table of all findings before the detailed write-ups.
  findings-summary-table(doc.findings, l)
  v(0.6em)

  for (i, f) in doc.findings.enumerate() {
    finding-heading(i + 1, f)

    // Location banner first — code audits lead with where the issue lives.
    location-banner(f)

    // CWE called out explicitly (in addition to the meta line).
    if f.cwe != "" {
      block(spacing: 6pt, text(size: 9pt, weight: "semibold", fill: accent, l.weakness + ": " + f.cwe))
    }
    finding-meta(f, l)

    // The vulnerable code snippet, prominent.
    if f.evidence_snippet != "" {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, l.vulnerable_code))
      code-block(f.evidence_snippet)
    }

    // Description facets — technical first for an audit audience.
    facet(l.summary, f.summary)
    facet(l.root_cause, f.root_cause)
    facet(l.technical_details, f.technical_details)
    facet(l.attack_vector, f.attack_vector)
    facet(l.business_impact, f.business_impact)

    // Affected assets (the finding↔asset link set).
    affected-assets(f, l.affected_assets)

    // Proof of Concept (optional, secondary in an audit).
    if f.has_poc {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, l.proof_of_concept))
      if f.poc_scenario != "" { block(spacing: 6pt, prose(f.poc_scenario)) }
      if f.poc_steps.len() > 0 {
        block(spacing: 6pt, enum(..f.poc_steps))
      }
      code-block(f.poc_payload)
    }

    // Evidence images (screenshots / diagrams).
    finding-images(f, l.screenshots)

    // Remediation — the fix description plus the suggested code patch.
    if f.fix != "" or f.code_patch != "" or f.remediation_refs.len() > 0 {
      facet(l.remediation, f.fix)
      if f.code_patch != "" {
        block(spacing: 6pt, text(size: 9pt, weight: "semibold", fill: accent, l.suggested_patch))
        code-block(f.code_patch)
      }
      references-block(f.remediation_refs, l.references)
    }

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
