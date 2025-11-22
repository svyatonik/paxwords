#![warn(missing_docs)]

pub use entry::*;
pub use metadata::*;
pub use order::*;
pub use secret::*;

mod entry;
mod metadata;
mod order;
mod secret;

// TODO: better to use something more stable than bincode

/// Bincode config used to serialize everything.
pub fn bincode_config() -> impl bincode::config::Config {
	bincode::config::standard()
		.with_little_endian()
		.with_fixed_int_encoding()
		.with_limit::<65_536>()
}
