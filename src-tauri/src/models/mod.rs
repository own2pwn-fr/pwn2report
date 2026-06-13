//! Domain models — Rust mirrors of the secai-core finding/report shapes,
//! trimmed to what the desktop report writer needs (no scan/lifecycle/taint
//! fields). Enums serialize as snake_case to match the secai wire format.

pub mod asset;
pub mod evidence_image;
pub mod finding;
pub mod kb;
pub mod report;
pub mod scope;

pub use asset::*;
pub use evidence_image::*;
pub use finding::*;
pub use kb::*;
pub use report::*;
pub use scope::*;

/// Distinguishes "field absent" (`None`) from "field present and null"
/// (`Some(None)`) when deserializing a patch object. Shared by every model's
/// `*Patch` for nullable scalar columns so a `null` clears the value while an
/// omitted field leaves it unchanged.
pub(crate) fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}
