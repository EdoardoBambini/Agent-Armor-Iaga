//! Embedded UI assets for Agent Armor 1.0.
//!
//! This module is compiled only when the `ui-embed` feature is enabled.
//! It embeds the production build of `ui/` (produced by `npm run build` into
//! `ui/dist/`) directly into the `agent-armor` / `armor` binary so that the
//! server can serve the dashboard without any external filesystem dependency.
//!
//! ## Build flow
//!
//! ```bash
//! cd ui && npm ci && npm run build    # produces ui/dist/
//! cd .. && cargo build -p agent-armor-core --features ui-embed
//! ```
//!
//! ## Wiring status (M1)
//!
//! M1 ships the embed module only. Serving these assets on an HTTP route
//! (`/ui`, `/ui/*path`) is scheduled for a later milestone — the placeholder
//! `dashboard` module is still the active UI surface in 0.4.0 behavior.
//!
//! ## Usage (future milestones)
//!
//! ```ignore
//! use agent_armor::ui_embed::UiAssets;
//! use rust_embed::RustEmbed;
//!
//! if let Some(index) = UiAssets::get("index.html") {
//!     // serve `index.data` with mimetype `index.metadata.mimetype()`
//! }
//! ```

use rust_embed::RustEmbed;

/// Static asset bundle for the Agent Armor UI.
///
/// Folder is resolved relative to the crate manifest at compile time
/// (`crates/armor-core/../../ui/dist`). Missing folder = compile error,
/// which is intentional — if you enabled `ui-embed` you must have built
/// the UI first.
#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../ui/dist"]
pub struct UiAssets;
