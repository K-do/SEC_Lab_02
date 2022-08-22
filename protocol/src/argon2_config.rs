use argon2::{Algorithm, Version};

/// Algorithm chosen: **Argon2id**
pub const ALGORITHM: Algorithm = Algorithm::Argon2id;

/// Version chosen: **19**
pub const VERSION: Version = Version::V0x13;

/// Memory cost chosen: **64 KiB**
pub const MEMORY: u32 = 65536; // As KiB

/// Number of passes chosen: **3**
pub const ITERATIONS: u32 = 3;

/// Number of lanes chosen: **4**
pub const LANES: u32 = 4;

/// Output length chosen: **64 B**
pub const OUTPUT_LENGTH: usize = 64;