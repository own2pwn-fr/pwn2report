// Shared helpers for pwn2report themes: severity color/label, badges,
// section headers, and the page header/footer. Kept robust to empty strings
// (the Rust render IR flattens all optional fields to "" / empty arrays).

// own2pwn severity palette.
#let severity-color(sev) = {
  if sev == "critical" { rgb("#dc2626") }
  else if sev == "high" { rgb("#ea580c") }
  else if sev == "medium" { rgb("#d97706") }
  else if sev == "low" { rgb("#2563eb") }
  else { rgb("#6b7280") } // info / unknown
}

// own2pwn accent violet.
#let accent = rgb("#7c5cff")

#let severity-label(sev) = upper(sev)

// A colored, rounded severity pill.
#let severity-badge(sev) = {
  box(
    fill: severity-color(sev),
    inset: (x: 8pt, y: 3pt),
    radius: 4pt,
    text(fill: white, weight: "bold", size: 8pt, severity-label(sev)),
  )
}

// A neutral small pill (for kind/confidence/tags).
#let tag-pill(label) = {
  box(
    fill: luma(235),
    inset: (x: 6pt, y: 2pt),
    radius: 3pt,
    text(size: 8pt, fill: luma(60), label),
  )
}

// Render a labelled facet block only when the body is non-empty.
#let facet(title, body) = {
  if body != none and body != "" {
    block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, title))
    block(spacing: 10pt, body)
  }
}

// A monospace code block (used for snippets, payloads, patches).
#let code-block(body) = {
  if body != none and body != "" {
    block(
      width: 100%,
      fill: luma(245),
      stroke: 0.5pt + luma(210),
      inset: 8pt,
      radius: 4pt,
      text(font: "JetBrains Mono", size: 8.5pt, raw(body)),
    )
  }
}

// Running page header/footer applied via `set page(...)` in the theme.
#let make-header(doc) = context {
  if counter(page).get().first() > 1 {
    set text(size: 8pt, fill: luma(140))
    grid(
      columns: (1fr, auto),
      align: (left, right),
      doc.title,
      doc.client,
    )
    line(length: 100%, stroke: 0.5pt + luma(220))
  }
}

#let make-footer() = context {
  set text(size: 8pt, fill: luma(140))
  set align(center)
  [#counter(page).display("1 / 1", both: true)]
}
