pub use apply::{LastChanceDecision, MergeAlgorithm, apply_remote_entries};
pub use compare::find_differences;
pub use retrieve::retrieve_entries;
pub use state::EntriesState;

use crate::{
	Error, ErrorKind,
	entries::InMemoryEntries,
	types::{Encrypted, Entry, EntryIndex, Hash, HashHalf},
};

use bincode::Encode;
use std::sync::Arc;

mod apply;
mod compare;
mod retrieve;
mod state;

/// State of peer entries storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerState {
	/// Total number of entries in the storage.
	pub entries_count: EntryIndex,
	/// L0 entries state hash.
	pub l0_hash: HashHalf,
}

/// Remote [Peer] suited for async retrieval.
pub trait Peer {
	/// Get overall peer sync state.
	fn sync_state(&self) -> impl Future<Output = Result<PeerState, Error>> + Send;

	/// Get all L1 hashes.
	fn l1_hashes(&self) -> impl Future<Output = Result<Vec<HashHalf>, Error>> + Send;

	/// Get L2 hashes for requested L1 chunk.
	fn l2_hashes(
		&self,
		l1_chunk_index: EntryIndex,
	) -> impl Future<Output = Result<Option<Vec<HashHalf>>, Error>> + Send;

	/// Get hashes of entries within given L2 hash.
	fn entry_hashes(
		&self,
		l2_chunk_index: EntryIndex,
	) -> impl Future<Output = Result<Option<Vec<HashHalf>>, Error>> + Send;

	/// Get entry.
	fn entry(
		&self,
		index: EntryIndex,
	) -> impl Future<Output = Result<Entry<Encrypted, Encrypted>, Error>>;
}

/// Local version of [Peer], which has sync methods.
pub trait LocalPeer {
	/// Get overall peer sync state.
	fn sync_state(&self) -> Result<PeerState, Error>;

	/// Get all L1 hashes.
	fn l1_hashes(&self) -> Result<Vec<HashHalf>, Error>;

	/// Get L2 hashes for requested L1 chunk. If return value is None, then this chunk
	/// is not in the local peers state.
	fn l2_hashes(&self, l1_chunk_index: EntryIndex) -> Result<Option<Vec<HashHalf>>, Error>;

	/// Get hashes of entries within given L2 hash. If return value is None, then this chunk
	/// is not in the local peers state.
	fn entry_hashes(&self, l2_chunk_index: EntryIndex) -> Result<Option<Vec<HashHalf>>, Error>;

	/// Get entry by index.
	fn entry(&self, index: EntryIndex) -> Result<Entry<Encrypted, Encrypted>, Error>;
}

impl<HeaderV: Clone + Encode> LocalPeer for Arc<InMemoryEntries<HeaderV>> {
	fn sync_state(&self) -> Result<PeerState, Error> {
		Ok(PeerState {
			entries_count: self.entries.len().try_into().unwrap(),
			l0_hash: self.state.l0_hash().half(),
		})
	}

	fn l1_hashes(&self) -> Result<Vec<HashHalf>, Error> {
		Ok(self.state.l1_hashes().iter().map(Hash::half).collect())
	}

	fn l2_hashes(&self, l1_chunk_index: EntryIndex) -> Result<Option<Vec<HashHalf>>, Error> {
		Ok(self
			.state
			.l1_chunk(l1_chunk_index)
			.map(|l1_chunk| l1_chunk.iter().map(Hash::half).collect()))
	}

	fn entry_hashes(&self, l2_chunk_index: EntryIndex) -> Result<Option<Vec<HashHalf>>, Error> {
		Ok(self
			.state
			.l2_chunk(l2_chunk_index)
			.map(|l2_chunk| l2_chunk.iter().map(Hash::half).collect()))
	}

	fn entry(&self, index: EntryIndex) -> Result<Entry<Encrypted, Encrypted>, Error> {
		self.entries
			.get(usize::from(index))
			.map(|entry| entry.encrypted_entry())
			.transpose()?
			.ok_or_else(|| Error::from(ErrorKind::InvalidEntryIndex(index)))
	}
}

impl<HeaderV: Clone + Encode> Peer for Arc<InMemoryEntries<HeaderV>> {
	fn sync_state(&self) -> impl Future<Output = Result<PeerState, Error>> + Send {
		futures::future::ready(LocalPeer::sync_state(self))
	}

	fn l1_hashes(&self) -> impl Future<Output = Result<Vec<HashHalf>, Error>> + Send {
		futures::future::ready(LocalPeer::l1_hashes(self))
	}

	fn l2_hashes(
		&self,
		l1_chunk_index: EntryIndex,
	) -> impl Future<Output = Result<Option<Vec<HashHalf>>, Error>> + Send {
		futures::future::ready(LocalPeer::l2_hashes(self, l1_chunk_index))
	}

	fn entry_hashes(
		&self,
		l2_chunk_index: EntryIndex,
	) -> impl Future<Output = Result<Option<Vec<HashHalf>>, Error>> + Send {
		futures::future::ready(LocalPeer::entry_hashes(self, l2_chunk_index))
	}

	fn entry(
		&self,
		index: EntryIndex,
	) -> impl Future<Output = Result<Entry<Encrypted, Encrypted>, Error>> {
		futures::future::ready(LocalPeer::entry(self, index))
	}
}
