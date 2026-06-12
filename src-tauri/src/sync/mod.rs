//! E2E-encrypted, local-first sync (v4).
//!
//! Sync is **serverless**: the whole vault's syncable data is snapshotted into a
//! [`bundle::SyncBundle`], serialized to JSON, and encrypted into a single age
//! passphrase-protected file ([`crypto`]). The user moves that file between
//! devices by any means (USB, Syncthing, Nextcloud, …). On the other side the
//! bundle is decrypted, parsed, and [`merge`]d into the local vault using a
//! per-row Last-Write-Wins CRDT keyed by the UUID primary key — conflict-free by
//! construction, order-independent.

pub mod bundle;
pub mod crypto;
pub mod merge;

pub use bundle::SyncBundle;
pub use merge::{merge, SyncSummary};
