//! Data-access layer: CRUD over the encrypted vault connection.
//!
//! Structured sub-objects are stored as JSON TEXT and (de)serialized with
//! serde_json here so the rest of the app deals only in typed models.

pub mod assets;
pub mod evidence;
pub mod findings;
pub mod kb;
pub mod reports;
pub mod scope;

use chrono::Utc;

/// Current RFC3339 UTC timestamp string (matches the secai convention).
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}
