//! DOCX renderer (via pandoc).
//!
//! Builds GitHub-flavored Markdown from the [`ReportDocument`] IR (reusing
//! [`super::markdown::to_markdown`]) then pipes it through `pandoc`:
//!
//! ```text
//! pandoc -f gfm -t docx --reference-doc=<reference.docx>
//! ```
//!
//! `pandoc` is resolved from `PATH` (or the `PWN2REPORT_PANDOC` override env
//! var). We do NOT bundle a pandoc binary or use tauri-plugin-shell. The
//! styling reference doc IS bundled (`include_bytes!`) and written to a temp
//! file for the `--reference-doc` flag. Markdown is fed on stdin; the docx is
//! captured on stdout.
//!
//! This is the only renderer that performs I/O (subprocess + temp file), kept
//! out of the pure `markdown`/`html` modules so those stay unit-testable.

use std::io::Write;
use std::process::{Command, Stdio};

use super::content_model::ReportDocument;
use super::markdown::to_markdown;
use crate::error::{AppError, AppResult};

/// Bundled pandoc reference doc carrying the own2pwn DOCX styling.
static REFERENCE_DOCX: &[u8] = include_bytes!("../../resources/pandoc/reference.docx");

/// Resolve the pandoc executable: honor `PWN2REPORT_PANDOC` if set, else rely
/// on `PATH` (just `"pandoc"`).
fn pandoc_bin() -> String {
    std::env::var("PWN2REPORT_PANDOC").unwrap_or_else(|_| "pandoc".to_string())
}

/// Render the report to DOCX bytes by piping GFM markdown through pandoc.
pub fn to_docx(doc: &ReportDocument) -> AppResult<Vec<u8>> {
    let markdown = to_markdown(doc);

    // Write the bundled reference doc to a uniquely-named temp file.
    let ref_path = std::env::temp_dir().join(format!(
        "pwn2report-reference-{}.docx",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&ref_path, REFERENCE_DOCX)?;

    let bin = pandoc_bin();
    let spawn = Command::new(&bin)
        .arg("-f")
        .arg("gfm")
        .arg("-t")
        .arg("docx")
        .arg(format!("--reference-doc={}", ref_path.display()))
        // stdin: markdown, stdout: docx bytes.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match spawn {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&ref_path);
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
            let _ = std::fs::remove_file(&ref_path);
            return Err(AppError::Pandoc(format!("failed writing to pandoc stdin: {e}")));
        }
        // Drop stdin to signal EOF before waiting (avoids a deadlock).
    }

    let output = child.wait_with_output();
    let _ = std::fs::remove_file(&ref_path);

    let output = output.map_err(|e| AppError::Pandoc(format!("pandoc failed: {e}")))?;
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
