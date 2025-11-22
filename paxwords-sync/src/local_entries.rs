use bincode::Encode;
use parking_lot::RwLock;
use paxwords_core::{
	Encrypted, EntriesState, Entry, EntryIndex, Error, ErrorKind, Hash, HashHalf, InMemoryEntries,
	LocalPeer, PeerState,
};
use std::sync::{Arc, Weak};
use tokio::sync::Notify;

/// Local entries container that implements [LocalPeer] trait.
pub struct LocalEntries<HeaderV> {
	/// Weak reference to current entries. If it fails to upgrade, it means that entries
	/// are currently changing and update will come soon. You may listen for updates using
	/// the [LocalEntries::wait_change] function.
	entries: Arc<RwLock<Weak<InMemoryEntries<HeaderV>>>>,
	/// Changes notifier.
	notify: Notify,
}

impl<HeaderV> Default for LocalEntries<HeaderV> {
	fn default() -> Self {
		Self {
			entries: Arc::new(RwLock::new(Default::default())),
			notify: Default::default(),
		}
	}
}

impl<HeaderV> LocalEntries<HeaderV> {
	/// Update entries.
	pub fn update(&self, new_entries: Weak<InMemoryEntries<HeaderV>>) {
		*self.entries.write() = new_entries;
		self.notify.notify_one();
	}

	/// Listen for entries change. Just one caller is assumed for this method.
	pub async fn wait_change(&self) {
		self.notify.notified().await;
	}
}

impl<HeaderV: Clone + Encode> LocalPeer for LocalEntries<HeaderV> {
	fn sync_state(&self) -> Result<PeerState, Error> {
		let entries = self
			.entries
			.read()
			.upgrade()
			.ok_or_else(|| Error::from(ErrorKind::StateUnavailable))?;
		Ok(PeerState {
			entries_count: EntriesState::entry_hashes(&entries.state)
				.len()
				.try_into()
				.expect("never more than u16::MAX entries in the storage; qed"),
			l0_hash: EntriesState::l0_hash(&entries.state).half(),
		})
	}

	fn l1_hashes(&self) -> Result<Vec<HashHalf>, Error> {
		let entries = self
			.entries
			.read()
			.upgrade()
			.ok_or_else(|| Error::from(ErrorKind::StateUnavailable))?;
		Ok(EntriesState::l1_hashes(&entries.state)
			.iter()
			.map(Hash::half)
			.collect())
	}

	fn l2_hashes(&self, l1_chunk_index: EntryIndex) -> Result<Option<Vec<HashHalf>>, Error> {
		let entries = self
			.entries
			.read()
			.upgrade()
			.ok_or_else(|| Error::from(ErrorKind::StateUnavailable))?;
		Ok(EntriesState::l1_chunk(&entries.state, l1_chunk_index)
			.map(|l1_chunk| l1_chunk.iter().map(Hash::half).collect()))
	}

	fn entry_hashes(&self, l2_chunk_index: EntryIndex) -> Result<Option<Vec<HashHalf>>, Error> {
		let entries = self
			.entries
			.read()
			.upgrade()
			.ok_or_else(|| Error::from(ErrorKind::StateUnavailable))?;
		Ok(EntriesState::l2_chunk(&entries.state, l2_chunk_index)
			.map(|l2_chunk| l2_chunk.iter().map(Hash::half).collect()))
	}

	fn entry(&self, index: EntryIndex) -> Result<Entry<Encrypted, Encrypted>, Error> {
		let entries = self
			.entries
			.read()
			.upgrade()
			.ok_or_else(|| Error::from(ErrorKind::StateUnavailable))?;
		entries
			.entries
			.get(usize::from(index))
			.map(|entry| entry.encrypted_entry())
			.transpose()?
			.ok_or_else(|| Error::from(ErrorKind::InvalidEntryIndex(index)))
	}
}
