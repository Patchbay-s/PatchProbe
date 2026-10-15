//! Comparaisons : scan ↔ scan et profil de site ↔ scan.

pub mod scan_diff;
pub mod site_profile_diff;

pub use scan_diff::{HostChangeKind, HostDiffEntry, ScanDiff};
pub use site_profile_diff::{SiteProfileDiff, SiteProfileDiffEntry, SiteProfileMatchKind};
