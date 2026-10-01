//! Copyright (c) 2026 freehelpdesk. Licensed under the MIT License.
//! See the LICENSE file in the repository root.
//!
//! Decrypt TeslaCam clips. The `tesdec` binary is a command-line wrapper
//! around this crate. C and C++ programs link the same build and include
//! `include/tesdec.h`.

pub mod api;
pub mod auth;
pub mod container;
pub mod ffi;
pub mod files;
pub mod net;

pub use api::{fetch_keys, item_for, FetchError, FetchedKeys, KeyRequestItem, MAX_BATCH};
pub use auth::{login, logout, refresh_session, session_for, status, Endpoints, Session, API_BASE};
pub use container::{
    decrypt_file, parse_container, probe, ClipHeader, Probe, HEADER_SIZE, PAGE_SIZE,
};
pub use ffi::{
    tesdec_decrypt_file, tesdec_fetch_keys, tesdec_max_batch, tesdec_probe, tesdec_version,
};
