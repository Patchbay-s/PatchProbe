//! Modèles de données partagés.

pub mod annotations;
pub mod device_type;
pub mod grouping;
pub mod host;
pub mod site_profile;
pub mod snapshot;
pub mod vendor_overrides;

pub use annotations::{Annotations, IpAnnotation};
pub use device_type::DeviceType;
pub use grouping::{group_hosts, GroupingOption, HostGroup};
pub use host::{scheme_for_port, url_for, Host, HostStatus};
pub use site_profile::{SiteProfile, SiteProfileEntry};
pub use snapshot::{HostSnapshot, ScanSnapshot};
pub use vendor_overrides::VendorOverrides;
