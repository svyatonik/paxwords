use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{EntryIndex, Error, ErrorKind, types::Hash};

/// Batch operation on entries. No changes are applied to the [EntriesState] until
/// [BatchOperation::commit] method is called.
pub struct BatchOperation<'a> {
	state: &'a mut EntriesState,
	entry_hashes: BTreeMap<u16, Hash>,
}

/// Completed, but uncomitted batch operation.
pub struct CompletedBatchOperation<'a> {
	state: &'a mut EntriesState,
	entry_hashes: BTreeMap<u16, Hash>,
	l2_invalidated: BTreeMap<u16, Hash>,
	l1_invalidated: BTreeMap<u16, Hash>,
	l0_hash: Hash,
}

impl<'a> BatchOperation<'a> {
	/// Get entry hash at given index. Returns updated entry hash or
	/// original entry hash.
	pub fn entry_hash(&self, index: EntryIndex) -> Option<&Hash> {
		self.entry_hashes
			.get(&index.into())
			.or_else(|| self.state.entry_hashes.get(usize::from(index)))
	}

	/// Entry at given `index` has been changed to value with given `hash`.
	pub fn change(&mut self, index: EntryIndex, hash: Hash) -> Result<(), Error> {
		// index must be:
		// 1) index of already existing entry
		// 2) index immediately following index of last known entry
		if usize::from(index) > self.state.entry_hashes.len() {
			match self
				.entry_hashes
				.last_key_value()
				.map(|(i, _)| usize::from(*i))
			{
				Some(new_last_entry_index) if usize::from(index) == new_last_entry_index + 1 => (),
				_ => {
					return Err(ErrorKind::InvalidEntryIndex(index).into());
				}
			}
		}

		self.entry_hashes.insert(index.into(), hash);
		Ok(())
	}

	/// Complete operations and precompute all hashes.
	pub fn complete(self) -> CompletedBatchOperation<'a> {
		let mut completed = CompletedBatchOperation {
			l0_hash: self.state.l0_hash,
			state: self.state,
			entry_hashes: self.entry_hashes,
			l2_invalidated: BTreeMap::new(),
			l1_invalidated: BTreeMap::new(),
		};

		tracing::trace!("completing update op: {:?}", completed.entry_hashes);

		if completed.entry_hashes.is_empty() {
			return completed;
		}

		// invalidate L2 chunks
		for index in completed.entry_hashes.keys() {
			let l2_index = index / 16;
			if completed
				.l2_invalidated
				.insert(l2_index, Hash::default())
				.is_none()
			{
				tracing::trace!("L2 chunk updated: {l2_index}");
			}
		}

		// recompute hashes of invalidated L2 chunks
		for (l2_index, l2_hash) in completed.l2_invalidated.iter_mut() {
			// invalidate L1 chunk
			let l1_index = l2_index / 16;
			if completed
				.l1_invalidated
				.insert(l1_index, Hash::default())
				.is_none()
			{
				tracing::trace!("L1 chunk updated: {l1_index}");
			}

			// recompute L2 hash
			let entries_range_begin = *l2_index as usize * 16;
			let entries_range_end = entries_range_begin + 16;
			let original_entries_range =
				std::cmp::min(entries_range_begin, completed.state.entry_hashes.len())
					..std::cmp::min(entries_range_end, completed.state.entry_hashes.len());
			let original_entries_range = &completed.state.entry_hashes[original_entries_range];
			*l2_hash = chunk_hash_with_overides(
				entries_range_begin,
				entries_range_end,
				original_entries_range,
				&completed.entry_hashes,
			);

			tracing::trace!("updated L2 chunk {l2_index} hash: {}", *l2_hash);
		}

		// recompute hashes of invalidated L1 chunks
		for (l1_index, l1_hash) in completed.l1_invalidated.iter_mut() {
			// recompute L1 hash
			let l2_range_begin = *l1_index as usize * 16;
			let l2_range_end = l2_range_begin + 16;
			let original_l2_range = std::cmp::min(l2_range_begin, completed.state.l2_hashes.len())
				..std::cmp::min(l2_range_end, completed.state.l2_hashes.len());
			let original_l2_range = &completed.state.l2_hashes[original_l2_range];
			*l1_hash = chunk_hash_with_overides(
				l2_range_begin,
				l2_range_end,
				original_l2_range,
				&completed.l2_invalidated,
			);

			tracing::trace!("updated L1 chunk {l1_index} hash: {}", *l1_hash);
		}

		// recompute l0 hash
		let l1_range_begin = 0;
		let l1_range_end = 16;
		let original_l1_range = std::cmp::min(l1_range_begin, completed.state.l1_hashes.len())
			..std::cmp::min(l1_range_end, completed.state.l1_hashes.len());
		let original_l1_range = &completed.state.l1_hashes[original_l1_range];
		completed.l0_hash = chunk_hash_with_overides(
			l1_range_begin,
			l1_range_end,
			original_l1_range,
			&completed.l1_invalidated,
		);
		tracing::trace!("updated L0 hash: {}", completed.l0_hash);

		completed
	}
}

impl<'a> CompletedBatchOperation<'a> {
	/// Return new L0 hash.
	pub fn l0_hash(&self) -> Hash {
		self.l0_hash
	}

	/// Commit batch operation by applying changes to linked [EntriesState].
	pub fn commit(self) {
		let mut last_entry_index = self.entry_hashes.last_key_value().map(|(k, _)| *k);
		if last_entry_index.is_none() {
			return;
		}

		// update entry hashes
		for (index, hash) in self.entry_hashes {
			// if entry was there before, we just need to change its hash
			if let Some(old_hash) = self.state.entry_hashes.get_mut(usize::from(index)) {
				*old_hash = hash;
				continue;
			}

			// we've got new entry - let's reserve more space for all new entries
			if let Some(last_entry_index) = last_entry_index.take() {
				let new_entries_end: u16 = last_entry_index;
				let new_entries_begin: u16 = index;
				let n_new_entries = new_entries_end - new_entries_begin + 1;
				self.state.entry_hashes.reserve(n_new_entries as usize);
			}

			// and remember its hash
			debug_assert_eq!(usize::from(index), self.state.entry_hashes.len());
			self.state.entry_hashes.push(hash);
		}

		// update hashes of invalidated L2 chunks
		for (l2_index, l2_chunk_hash) in self.l2_invalidated {
			let l2_index = l2_index as usize;
			if l2_index < self.state.l2_hashes.len() {
				self.state.l2_hashes[l2_index] = l2_chunk_hash;
			} else {
				debug_assert_eq!(l2_index, self.state.l2_hashes.len());
				self.state.l2_hashes.push(l2_chunk_hash);
			}
		}

		// update hashes of invalidated L1 chunks
		for (l1_index, l1_chunk_hash) in self.l1_invalidated {
			let l1_index = l1_index as usize;
			if l1_index < self.state.l1_hashes.len() {
				self.state.l1_hashes[l1_index] = l1_chunk_hash;
			} else {
				debug_assert_eq!(l1_index, self.state.l1_hashes.len());
				self.state.l1_hashes.push(l1_chunk_hash);
			}
		}

		// recompute l0 hash
		self.state.l0_hash = self.l0_hash;
	}
}

/// Entries state, used in sync protocol. It holds at most 69_889 hashes (2_236_448 bytes).
/// Which is acceptable, given that for most use cases there are much fewer passwords
/// in the storage. OTOH it speeds up a sync process.
///
/// **WARNING**: try not to clone this structure, because it is quite heavy. In core, the
/// structure is only cloned on write, if no other holders are watching it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EntriesState {
	/// Single hash, representing the whole state.
	l0_hash: Hash,
	/// At most 256 hashes (256 L1 chunks x 256 entries each = 65_536).
	l1_hashes: Vec<Hash>,
	/// At most 4096 hashes (256 L1 chunks x 16 L2 chunks x 16 entries each = 65_536)
	l2_hashes: Vec<Hash>,
	/// At most 65_536 hashes.
	entry_hashes: Vec<Hash>,
}

impl EntriesState {
	/// Create entries state with given number of entries.
	pub fn with_capacity(n_entries: usize) -> Self {
		Self {
			l1_hashes: Vec::with_capacity(n_entries / 256),
			l2_hashes: Vec::with_capacity(n_entries / 16),
			entry_hashes: Vec::with_capacity(n_entries),
			..Default::default()
		}
	}

	/// Begin batch operation on the state.
	pub fn batch_op<'a>(&'a mut self) -> BatchOperation<'a> {
		BatchOperation {
			state: self,
			entry_hashes: Default::default(),
		}
	}

	/// Return single hash, describing all the entries in the storage.
	pub fn l0_hash(&self) -> Hash {
		self.l0_hash
	}

	/// Return reference to all L1 hashes.
	pub fn l1_hashes(&self) -> &[Hash] {
		&self.l1_hashes
	}

	/// Return all L2 hashes, which are part of given L1 chunk.
	pub fn l1_chunk(&self, l1_index: EntryIndex) -> Option<&[Hash]> {
		let n_l2_chunks = self.l2_hashes.len();
		let l1_chunk_begin_index = usize::from(l1_index) * 16;
		if l1_chunk_begin_index >= n_l2_chunks {
			return None;
		}

		let l1_chunk_end_index = std::cmp::min(l1_chunk_begin_index + 16, n_l2_chunks);
		Some(&self.l2_hashes[l1_chunk_begin_index..l1_chunk_end_index])
	}

	/// Return reference to all L2 hashes.
	pub fn l2_hashes(&self) -> &[Hash] {
		&self.l2_hashes
	}

	/// Return all entry hashes, which are part of given L2 chunk.
	pub fn l2_chunk(&self, l2_index: EntryIndex) -> Option<&[Hash]> {
		let n_entries = self.entry_hashes.len();
		let l2_chunk_begin_index = usize::from(l2_index) * 16;
		if l2_chunk_begin_index >= n_entries {
			return None;
		}

		let l2_chunk_end_index = std::cmp::min(l2_chunk_begin_index + 16, n_entries);
		Some(&self.entry_hashes[l2_chunk_begin_index..l2_chunk_end_index])
	}

	/// Return reference to all entry hashes.
	pub fn entry_hashes(&self) -> &[Hash] {
		&self.entry_hashes
	}
}

fn chunk_hash_with_overides(
	mut hash_index: usize,
	hashes_end_index: usize,
	hashes: &[Hash],
	overrides: &BTreeMap<u16, Hash>,
) -> Hash {
	let hashes_begin_index = hash_index;
	let mut chunk_hash = Sha256::new();
	while hash_index < hashes_end_index {
		let hash = match hash_index
			.try_into()
			.ok()
			.and_then(|idx| overrides.get(&idx))
			.cloned()
		{
			Some(hash_override) => hash_override,
			None => match hashes.get(hash_index - hashes_begin_index) {
				Some(hash) => *hash,
				None => break,
			},
		};
		chunk_hash.update(hash.0);
		hash_index += 1;
	}
	Hash(chunk_hash.finalize().into())
}

#[cfg(test)]
mod tests {
	use super::*;

	use assert_matches::assert_matches;
	use hex_literal::hex;

	fn hash_of(index: u16) -> Hash {
		let mut hasher = sha2::Sha256::new();
		hasher.update(index.to_be_bytes());
		Hash(hasher.finalize().into())
	}

	#[test]
	fn may_change_next_item() {
		let mut state = EntriesState::with_capacity(0);
		// fill by adding next item in a separate op
		for i in 0..u16::MAX {
			let mut op = state.batch_op();
			op.change(i.into(), hash_of(i)).unwrap();
			op.complete().commit();
		}
		assert_eq!(state.entry_hashes.len(), u16::MAX as usize)
	}

	#[test]
	fn may_change_old_item() {
		let mut state = EntriesState::with_capacity(0);
		// add all entries in first op
		let mut op = state.batch_op();
		for i in 0..u16::MAX {
			op.change(i.into(), hash_of(i)).unwrap();
		}
		op.complete().commit();
		// change all entries in 2nd op
		let mut op = state.batch_op();
		for i in 0..u16::MAX {
			op.change(i.into(), hash_of(i)).unwrap();
		}
		op.complete().commit();
	}

	#[test]
	fn may_change_item_twice() {
		let mut state = EntriesState::with_capacity(0);
		// add item in first op
		let mut op = state.batch_op();
		op.change(0u16.into(), hash_of(0)).unwrap();
		op.complete().commit();
		// change old and new items twice in first op
		let mut op = state.batch_op();
		op.change(0u16.into(), hash_of(10)).unwrap();
		op.change(1u16.into(), hash_of(11)).unwrap();
		op.change(0u16.into(), hash_of(20)).unwrap();
		op.change(1u16.into(), hash_of(21)).unwrap();
		op.complete().commit();
	}

	#[test]
	fn empty_state_works() {
		let state = EntriesState::with_capacity(0);
		assert_eq!(state.l0_hash(), Hash::default());
		assert_eq!(state.l1_hashes(), &[]);
		assert_eq!(state.l1_chunk(0.into()), None);
		assert_eq!(state.l2_hashes(), &[]);
		assert_eq!(state.l2_chunk(0.into()), None);
		assert_eq!(state.entry_hashes(), &[]);
	}

	#[test]
	fn edge_changes_work() {
		let mut state = EntriesState::with_capacity(0);
		// insert 512 entries
		let mut op = state.batch_op();
		for i in 0..512 {
			op.change(i.into(), hash_of(i)).unwrap();
		}
		op.complete().commit();
		// add entry#513 and check that old L1 and L2 hashes are left intact
		let old_l1_hashes = state.l1_hashes.clone();
		let old_l2_hashes = state.l2_hashes.clone();
		let mut op = state.batch_op();
		op.change(512u16.into(), hash_of(0)).unwrap();
		op.complete().commit();
		assert_eq!(old_l1_hashes, state.l1_hashes[..state.l1_hashes.len() - 1]);
		assert_eq!(old_l2_hashes, state.l2_hashes[..state.l2_hashes.len() - 1]);
		// change entry#256 and check that only one L1 and one L2 hash is changed
		let old_l1_hashes = state.l1_hashes.clone();
		let old_l2_hashes = state.l2_hashes.clone();
		let mut op = state.batch_op();
		op.change(255u16.into(), hash_of(0)).unwrap();
		op.complete().commit();
		assert_eq!(old_l1_hashes[1..], state.l1_hashes[1..]);
		assert_ne!(old_l1_hashes[0], state.l1_hashes[0]);
		assert_eq!(old_l2_hashes[..15], state.l2_hashes[..15]);
		assert_eq!(old_l2_hashes[16..], state.l2_hashes[16..]);
		assert_ne!(old_l2_hashes[15], state.l2_hashes[15]);
	}

	#[test]
	fn state_works() {
		let mut state = EntriesState::with_capacity(1);

		// new change operation is started
		let mut op = state.batch_op();
		// we change (add) entry 0 - it is ok
		op.change(0.into(), hash_of(0)).unwrap();
		// try to add non-consequent item => err
		assert_matches!(
			op.change(2.into(), hash_of(2)),
			Err(Error::Base(ErrorKind::InvalidEntryIndex(idx))) if 2u16 == idx.into()
		);
		// another consequent => ok
		op.change(1u16.into(), hash_of(1)).unwrap();
		op.change(2u16.into(), hash_of(2)).unwrap();

		// commit
		op.complete().commit();

		// and check that entries are added
		assert_eq!(state.entry_hashes(), &[hash_of(0), hash_of(1), hash_of(2)]);
		// check some hardcoded values
		// L2[0] = hash(hash(0) ++ hash(1) ++ hash(2))
		assert_eq!(
			state.l2_hashes(),
			&[Hash(hex!(
				"adb0a0f2873969c7f72f345aa4b3de8a9e3b0d3661966e7491695fa6402ec51b"
			))]
		);
		// L1[0] = hash(L2[0])
		assert_eq!(
			state.l1_hashes(),
			&[Hash(hex!(
				"fe1fd3f936fee0c33f9eb960c9c506f9d7405a70e7e4266e278f36f70829c4ca"
			))]
		);
		// L0 = hash(L1[0])
		assert_eq!(
			state.l0_hash(),
			Hash(hex!(
				"0120ccbeaa06c269bf9241e7375413f179d05ed9529f86ae38776fb1f9f77f01"
			))
		);

		// add some more hashes so we have two L2 chunks
		let mut op = state.batch_op();
		for i in 3..20 {
			op.change(i.into(), hash_of(i)).unwrap();
		}
		op.complete().commit();

		// and check that entries are added
		assert_eq!(
			state.entry_hashes(),
			&(0..20).map(hash_of).collect::<Vec<_>>()
		);
		// check some hardcoded values
		// L2[0] = hash(hash(0) ++ ... ++ hash(15)), L2[1] = hash(hash(16) ++ ... ++ hash(19))
		assert_eq!(
			state.l2_hashes(),
			&[
				Hash(hex!(
					"cfc343aafe51ed6a8bf4e4c0a6cdb2acaf12a23e21a3727869ed830bcc17f990"
				)),
				Hash(hex!(
					"a65ca9f1a58d3d6018a9d956e3b4d3443655d02e7cb08bfe1f08212ddc1e4d05"
				))
			]
		);
		// L1[0] = hash(L2[0] ++ L2[1])
		assert_eq!(
			state.l1_hashes(),
			&[Hash(hex!(
				"31df12400f978a1c7d686860a5bb6d2b31a28ae0a20f49c037f799ab885258a7"
			))]
		);
		// L0 = hash(L1[0])
		assert_eq!(
			state.l0_hash(),
			Hash(hex!(
				"1213caf5f09e42e8e0476303b3a0e5ffb915a39478a3c3f2ae881385857ca2c5"
			))
		);
	}
}
