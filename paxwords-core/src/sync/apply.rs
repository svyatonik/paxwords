use crate::{
	Encrypted, EntriesBatchOp, EntriesOrder, Entry, EntryIndex, Error, ErrorKind, InMemoryEntry,
	MasterPassword, Unencrypted, entries::EntryEncrypter,
};

use bincode::{Decode, Encode};
use std::sync::Arc;
use thiserror_context::Context;
use zeroize::Zeroize;

/// Last chance decision before we drop remote entry.
#[derive(Clone, Copy, Debug)]
pub enum LastChanceDecision {
	/// Remote entry is merged into local entry with `merge_with` index.
	MergeInto {
		/// Merge remote entry into local entry with given index.
		merge_with: EntryIndex,
	},
	/// Discard remote entry.
	Discard,
}

/// Entries merge algorithm. The algorithm must be consistent and behave the same
/// way on all peers that share the same master key.
pub trait MergeAlgorithm<HeaderV, BodyV>: EntriesOrder<HeaderV = HeaderV> {
	/// Merge two entries into single one. Entries that are merged are guaranteed
	/// to be equal w.r.t. [MergeAlgorithm::cmp] ordering.
	fn merge(
		into: InMemoryEntry<HeaderV>,
		what: &InMemoryEntry<HeaderV>,
	) -> Result<Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>, Error>;
	/// Last chance call before remote entry is discarded. It is called when we already
	/// have 65_536 local entries and new remote entry is received. Then, instead of
	/// discarding anything, the [MergeAlgorithm] shall decide - what to do. As with other
	/// methods, the decision must be consisntent on all syncing peers.
	fn last_chance(remote_entry: &InMemoryEntry<HeaderV>) -> LastChanceDecision;
}

/// Batch builder.
struct BatchBuilder<HeaderV> {
	/// Index of the next new entry. None if we're ubable to get any more entries.
	new_length: Option<EntryIndex>,
	/// Current batch.
	batch: Vec<EntriesBatchOp<HeaderV>>,
}

impl<HeaderV> BatchBuilder<HeaderV> {
	fn new(local_entries: &[Arc<InMemoryEntry<HeaderV>>]) -> Self {
		Self {
			new_length: u16::try_from(local_entries.len()).map(Into::into).ok(),
			batch: Vec::new(),
		}
	}

	fn is_full(&self) -> bool {
		self.new_length.is_none()
	}

	fn insert(&mut self, entry: Arc<InMemoryEntry<HeaderV>>) -> Result<(), Error> {
		// check that we're still in storage limits
		self.new_length = self
			.new_length
			.ok_or_else(|| Error::from(ErrorKind::TooManyEntries))?
			.next_index();
		// queue entry creation op
		self.batch.push(EntriesBatchOp::InsertEntry { entry });
		Ok(())
	}

	fn update(
		&mut self,
		old_entry: Arc<InMemoryEntry<HeaderV>>,
		entry: Arc<InMemoryEntry<HeaderV>>,
	) {
		self.batch
			.push(EntriesBatchOp::UpdateEntry { old_entry, entry });
	}

	fn build(self) -> Vec<EntriesBatchOp<HeaderV>> {
		self.batch
	}
}

/// Prepare a batch of command to apply remote entries to local storage.
/// [remote_entries] cannot contain duplicates or apply batch will fail
/// and it may lead to infinite compare-retrieve-apply loop.
pub fn apply_remote_entries<A, HeaderV, BodyV>(
	master: &Arc<MasterPassword>,
	local_entries: &[Arc<InMemoryEntry<HeaderV>>],
	remote_entries: Vec<Entry<Encrypted, Encrypted>>,
) -> Result<Vec<EntriesBatchOp<HeaderV>>, Error>
where
	A: MergeAlgorithm<HeaderV, BodyV>,
	HeaderV: Decode<()> + Encode + Zeroize,
	BodyV: Decode<()> + Encode + Zeroize,
{
	let mut batch = BatchBuilder::new(local_entries);
	for remote_entry in remote_entries {
		// try to find local entry that has the same user key as remote entry
		let remote_entry = master
			.create_from_encrypted_entry::<BodyV>(remote_entry)
			.context("creating new entry from encrypted remote")?;
		if let Ok(local_index) =
			local_entries.binary_search_by(|local| A::cmp(local.entry(), remote_entry.entry()))
		{
			// we found one => merge remote entry into local
			let local_entry = local_entries[local_index].clone();
			tracing::debug!(
				"going to merge local entry {local_entry:?} with remote {remote_entry:?}"
			);
			let updated_entry =
				A::merge(remote_entry, &local_entry).context("merging local and remote entries")?;
			let updated_entry = master
				.create_from_plain_entry::<BodyV>(updated_entry)
				.context("creating new entry from plain merged")?;
			batch.update(local_entry, Arc::new(updated_entry));
			continue;
		}

		// if we need to create another entry, but we're already full
		if batch.is_full() {
			match A::last_chance(&remote_entry) {
				LastChanceDecision::Discard => (),
				LastChanceDecision::MergeInto { merge_with } => {
					let Some(local_entry) = local_entries.get(usize::from(merge_with)) else {
						continue;
					};
					let updated_entry = A::merge(remote_entry, local_entry)
						.context("merging local and remote entries")?;
					let updated_entry = master
						.create_from_plain_entry::<BodyV>(updated_entry)
						.context("creating new entry from plain merged")?;
					batch.update(local_entry.clone(), Arc::new(updated_entry));
				}
			}
			continue;
		}

		// we haven't found local entry with the same user key => insert into corresponding position
		tracing::debug!("going to add remote entry {remote_entry:?}");
		batch.insert(Arc::new(remote_entry))?;
	}

	Ok(batch.build())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::*;

	use assert_matches::assert_matches;
	use std::sync::atomic::Ordering;

	#[test]
	fn last_chance_called_when_there_are_too_many_local_entries() {
		// when locally we have maximal number of entries
		let local_entries = (0u16..=u16::MAX)
			.map(|index| in_memory_entry(index as _))
			.collect::<Vec<_>>();
		// and we've got new remote entry
		let remote_plain_entry = plain_entry_with_key(u64::MAX, 5);
		let remote_entry = master()
			.create_from_plain_entry(remote_plain_entry)
			.unwrap()
			.encrypted_entry()
			.unwrap();
		let remote_entries = vec![remote_entry];

		// then apply shall
		let result = apply_remote_entries::<TestMergeAlgorithm, _, _>(
			&master(),
			&local_entries,
			remote_entries.clone(),
		);
		// ..call the last_chance
		assert!(LAST_CHANCE_CALLED.load(Ordering::SeqCst));
		// ..and we still get the Ok()
		assert_matches!(result.map(drop), Ok(()));

		// when MergeAlgorithm selects merge
		LAST_CHANCE_MERGE_INTO.store(5, Ordering::SeqCst);
		LAST_CHANCE_CALLED.store(false, Ordering::SeqCst);
		// then apply shall
		let mut batch = apply_remote_entries::<TestMergeAlgorithm, _, _>(
			&master(),
			&local_entries,
			remote_entries,
		)
		.unwrap();
		// ..call the last_chance
		assert!(LAST_CHANCE_CALLED.load(Ordering::SeqCst));
		// ..and return single update op
		assert_eq!(batch.len(), 1);
		match batch.remove(0) {
			EntriesBatchOp::UpdateEntry { old_entry, entry } => {
				assert!(Arc::ptr_eq(&old_entry, &local_entries[5]));
				let new_entry_plain = entry.decrypt::<u64>().unwrap();
				assert_eq!(new_entry_plain.value(), 10);
			}
			_ => unreachable!("UpdateEntryAt is expected"),
		}
	}

	#[test]
	fn apply_inserts_new_remote_entry() {
		// when locally we have entry#0 with value 4
		let local_plain_entry = plain_entry_with_key(0, 4);
		let local_entry = master().create_from_plain_entry(local_plain_entry).unwrap();
		let local_entries = [Arc::new(local_entry)];
		// and we've got remote entry#1 with value 42
		let remote_plain_entry = plain_entry_with_key(1, 42);
		let remote_entry = master()
			.create_from_plain_entry(remote_plain_entry)
			.unwrap();
		let remote_entry = remote_entry.encrypted_entry().unwrap();
		let remote_entries = vec![remote_entry];

		// then we merge them
		let mut batch = apply_remote_entries::<TestMergeAlgorithm, _, _>(
			&master(),
			&local_entries,
			remote_entries,
		)
		.unwrap();
		// and get a single update op with value set to 42+4
		assert_eq!(batch.len(), 1);
		match batch.remove(0) {
			EntriesBatchOp::InsertEntry { entry } => {
				let new_entry_plain = entry.decrypt::<u64>().unwrap();
				assert_eq!(new_entry_plain.value(), 42);
			}
			_ => unreachable!("UpdateEntryAt is expected"),
		}
	}

	#[test]
	fn apply_merges_two_identical_entries() {
		// when locally we have entry#0 with value 4
		let local_plain_entry = plain_entry_with_key(0, 4);
		let local_entry = master().create_from_plain_entry(local_plain_entry).unwrap();
		let local_entries = [Arc::new(local_entry)];
		// and we've got remote entry#0 with value 42
		let remote_plain_entry = plain_entry_with_key(0, 42);
		let remote_entry = master()
			.create_from_plain_entry(remote_plain_entry)
			.unwrap();
		let remote_entry = remote_entry.encrypted_entry().unwrap();
		let remote_entries = vec![remote_entry];

		// then we merge them
		let mut batch = apply_remote_entries::<TestMergeAlgorithm, _, _>(
			&master(),
			&local_entries,
			remote_entries,
		)
		.unwrap();
		// and get a single update op with value set to 42+4
		assert_eq!(batch.len(), 1);
		match batch.remove(0) {
			EntriesBatchOp::UpdateEntry { old_entry, entry } => {
				assert!(Arc::ptr_eq(&old_entry, &local_entries[0]));
				let new_entry_plain = entry.decrypt::<u64>().unwrap();
				assert_eq!(new_entry_plain.value(), 46);
			}
			_ => unreachable!("UpdateEntryAt is expected"),
		}
	}
}
