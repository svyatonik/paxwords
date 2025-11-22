use super::Hash;

use bincode::{Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Entries metadata.
#[derive(Decode, Default, Encode, Zeroize, ZeroizeOnDrop)]
pub struct Metadata {
	/// L0 hash of all entries.
	pub l0_hash: Hash,
}
