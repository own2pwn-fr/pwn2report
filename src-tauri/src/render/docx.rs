//! DOCX renderer (via pandoc).
//!
//! Builds GitHub-flavored Markdown from the [`ReportDocument`] IR (reusing
//! [`super::markdown::to_markdown_with`]) then pipes it through `pandoc`:
//!
//! ```text
//! pandoc -f gfm -t docx --reference-doc=<reference.docx> --resource-path=<tmp>
//! ```
//!
//! `pandoc` is resolved from `PATH` (or the `PWN2REPORT_PANDOC` override env
//! var). We do NOT bundle a pandoc binary or use tauri-plugin-shell. The
//! styling reference doc IS bundled (`include_bytes!`) and written to a temp
//! file for the `--reference-doc` flag. Markdown is fed on stdin; the docx is
//! captured on stdout.
//!
//! Evidence images: pandoc does NOT embed data-URI images reliably, so each
//! image is written to a per-call temp dir as a real file and referenced from
//! the markdown by relative path; `--resource-path=<tmp>` lets pandoc resolve
//! and embed them. The temp dir is removed on every exit path.
//!
//! This is the only renderer that performs I/O (subprocess + temp files), kept
//! out of the pure `markdown`/`html` modules so those stay unit-testable.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::content_model::ReportDocument;
use super::markdown::{to_markdown_with, ImageMode};
use crate::error::{AppError, AppResult};

/// Bundled pandoc reference doc carrying the own2pwn DOCX styling.
static REFERENCE_DOCX: &[u8] = include_bytes!("../../resources/pandoc/reference.docx");

/// Resolve the pandoc executable: honor `PWN2REPORT_PANDOC` if set, else rely
/// on `PATH` (just `"pandoc"`).
fn pandoc_bin() -> String {
    std::env::var("PWN2REPORT_PANDOC").unwrap_or_else(|_| "pandoc".to_string())
}

/// Map a MIME type to a file extension for the temp image files. Defaults to
/// `png` for the common screenshot case / unknown types.
fn ext_for_mime(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/bmp" => "bmp",
        _ => "png",
    }
}

/// Deterministic relative filename for finding `i`, image `j`.
fn image_filename(i: usize, j: usize, mime: &str) -> String {
    format!("img-{i}-{j}.{}", ext_for_mime(mime))
}

/// Render the report to DOCX bytes by feeding GFM markdown to pandoc.
///
/// Evidence images are written to a per-call temp dir as real files and the
/// markdown references them by relative path (pandoc does NOT embed data-URI
/// images reliably); `--resource-path=<tempdir>` lets pandoc resolve and embed
/// them. The reference styling doc lives in the same temp dir. The whole dir is
/// removed on every exit path (success or error).
pub fn to_docx(doc: &ReportDocument) -> AppResult<Vec<u8>> {
    // Per-call temp working dir holding the reference doc + image files.
    let work_dir = std::env::temp_dir().join(format!("pwn2report-docx-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&work_dir)?;

    // Everything below may fail; ensure the temp dir is removed regardless by
    // running the body in a closure and cleaning up afterwards.
    let result = render_in_dir(doc, &work_dir);
    let _ = std::fs::remove_dir_all(&work_dir);
    result
}

/// Body of [`to_docx`], operating inside an already-created `work_dir`. The
/// caller is responsible for removing `work_dir` on all paths.
fn render_in_dir(doc: &ReportDocument, work_dir: &Path) -> AppResult<Vec<u8>> {
    // Write each finding's images to disk and build the relative-path resolver.
    // Indexing mirrors `markdown::push_finding`'s `(finding_idx, image_idx)`.
    let mut paths: Vec<Vec<String>> = Vec::with_capacity(doc.findings.len());
    for (i, f) in doc.findings.iter().enumerate() {
        let mut finding_paths = Vec::with_capacity(f.images.len());
        for (j, img) in f.images.iter().enumerate() {
            let name = image_filename(i, j, &img.mime);
            std::fs::write(work_dir.join(&name), img.data.as_slice())?;
            finding_paths.push(name);
        }
        paths.push(finding_paths);
    }

    let resolve = |i: usize, j: usize| -> String {
        paths
            .get(i)
            .and_then(|v| v.get(j))
            .cloned()
            .unwrap_or_default()
    };
    let markdown = to_markdown_with(doc, &ImageMode::Paths(&resolve));

    // Write the bundled reference doc into the temp dir.
    let ref_path: PathBuf = work_dir.join("reference.docx");
    std::fs::write(&ref_path, REFERENCE_DOCX)?;

    let bin = pandoc_bin();
    let spawn = Command::new(&bin)
        .arg("-f")
        .arg("gfm")
        .arg("-t")
        .arg("docx")
        .arg(format!("--reference-doc={}", ref_path.display()))
        // Resolve relative image paths against the temp dir (and embed them).
        .arg(format!("--resource-path={}", work_dir.display()))
        // stdin: markdown, stdout: docx bytes.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match spawn {
        Ok(c) => c,
        Err(e) => {
            return Err(AppError::Pandoc(format!(
                "could not run pandoc ('{bin}'): {e}. \
                 Install pandoc (https://pandoc.org/installing.html) and ensure \
                 it is on your PATH, or set PWN2REPORT_PANDOC to its full path."
            )));
        }
    };

    // Feed the markdown via stdin, then wait for the docx on stdout.
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(markdown.as_bytes()) {
            return Err(AppError::Pandoc(format!("failed writing to pandoc stdin: {e}")));
        }
        // Drop stdin to signal EOF before waiting (avoids a deadlock).
    }

    let output = child
        .wait_with_output()
        .map_err(|e| AppError::Pandoc(format!("pandoc failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Pandoc(format!(
            "pandoc exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    Ok(output.stdout)
}
