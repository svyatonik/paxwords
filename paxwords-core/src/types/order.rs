use super::{Encrypted, Entry, Unencrypted};

use std::cmp::Ordering;

/// A strict entries order. Entries are always stored as a vector, sorted w.r.t.
/// this order.
pub trait EntriesOrder {
	/// Type of unencrypted header values. It is used by entry comparison operation.
	type HeaderV;

	/// Compare two entries with unencrypted headers.
	fn cmp(
		left: &Entry<Unencrypted<Self::HeaderV>, Encrypted>,
		right: &Entry<Unencrypted<Self::HeaderV>, Encrypted>,
	) -> Ordering;
}
