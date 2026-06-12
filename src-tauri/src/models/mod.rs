//! Domain models — Rust mirrors of the secai-core finding/report shapes,
//! trimmed to what the desktop report writer needs (no scan/lifecycle/taint
//! fields). Enums serialize as snake_case to match the secai wire format.

pub mod evidence_image;
pub mod finding;
pub mod kb;
pub mod report;

pub use evidence_image::*;
pub use finding::*;
pub use kb::*;
pub use report::*;
