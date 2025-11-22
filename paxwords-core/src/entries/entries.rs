use super::{
	InMemoryEntries, InMemoryEntry, entry_encrypter::EntryEncrypter, storage::FileStorage,
};
use crate::{
	Encrypted, Error, ErrorKind,
	crypto::MasterPassword,
	sync::EntriesState,
	types::{EntriesOrder, Entry, EntryIndex, Hash, Metadata, Unencrypted, bincode_config},
};

use bincode::{Decode, Encode, de::read::SliceReader};
use secrecy::ExposeSecret;
use std::{
	io::{Read, Write},
	path::Path,
	sync::{Arc, Weak},
};
use thiserror_context::Context;
use zeroize::Zeroize;

/// A single operation on [Entries]. Multiple operations may be applied at once
/// (atomically) using [Entries::apply_batch].
#[derive(Debug)]
pub enum EntriesBatchOp<HeaderV> {
	/// Create new entry.
	InsertEntry {
		/// A new entry.
		entry: Arc<InMemoryEntry<HeaderV>>,
	},
	/// Update existing entry.
	UpdateEntry {
		/// Old entry. It is used to check whether the entry has been updated since
		/// operation creation. If it has been changed, operation fails.
		old_entry: Arc<InMemoryEntry<HeaderV>>,
		/// An updated entry.
		entry: Arc<InMemoryEntry<HeaderV>>,
	},
}

/// Secret entries.
pub struct Entries<Order: EntriesOrder> {
	/// File storage.
	storage: FileStorage,
	/// Master password.
	master: Arc<MasterPassword>,
	/// Current storage entries with changes that are not yet flushed to disk.
	unflushed_entries: UnflushedEntries<Order>,
	/// Current storage entries that are guaranteed to be on disk. It is 'owned' by this
	/// structure, but other components may store references, so when we need to modify
	/// state, we use copy-on-write approach using `Arc::make_mut`.
	flushed_entries: Arc<InMemoryEntries<Order::HeaderV>>,
}

impl<Order: EntriesOrder> std::fmt::Debug for Entries<Order> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Entries")
	}
}

struct UnflushedEntries<Order: EntriesOrder> {
	/// Master password.
	master: Arc<MasterPassword>,
	/// Current storage entries with changes that are not yet flushed to disk. It
	/// is 'owned' by this structure, but other components may store references, so
	/// when we need to modify state, we use copy-on-write approach using `Arc::make_mut`.
	entries: Arc<Vec<Arc<InMemoryEntry<Order::HeaderV>>>>,
}

/// Secret as it is stored in a storage. This structure is encrypted with the `master`
/// so we get nice feature - we don't need to decrypt [Self::encrypted] to compute hash.
/// Another neutral feature is that we encrypt the same data twice, but since we use
/// different nonces every time, it should be ok.
#[derive(Decode, Encode)]
struct HashedEncrypted<T> {
	/// Hash of the unencrypted [Self::encrypted] data.
	hash: Hash,
	/// Encrypted data.
	encrypted: T,
}

impl<Order: EntriesOrder> Entries<Order>
where
	Order::HeaderV: Clone + Decode<()> + Encode + Zeroize,
{
	/// Create new entries from given storage.
	pub fn new(path: &Path, master: Arc<MasterPassword>) -> Result<Self, Error> {
		let storage = FileStorage::at(path)?;
		let flushed_entries = if !storage.is_empty()? {
			let master = master.clone();
			storage.read(move |reader| Self::from_reader(master, reader))?
		} else {
			InMemoryEntries::<Order::HeaderV>::default()
		};

		let flushed_entries = Arc::new(flushed_entries);
		let unflushed_entries = UnflushedEntries {
			master: master.clone(),
			entries: flushed_entries.entries.clone(),
		};
		Ok(Self {
			storage,
			master,
			unflushed_entries,
			flushed_entries,
		})
	}

	/// Return master password reference.
	pub fn master(&self) -> &Arc<MasterPassword> {
		&self.master
	}

	/// Return weak reference to current set of entries. The caller may clone and
	/// hold the reference, but it is better to hold weak reference instead and
	/// upgrade only when required. In this case, the underlying `Vec<InMemoryEntry>`
	/// and `EntriesState`` won't be cloned during updates.
	///
	/// Flushed entries are supposed to be used in e.g. sync where we need to be sure
	/// that we're using persistent version of entries.
	pub fn unflushed_entries(&self) -> Weak<Vec<Arc<InMemoryEntry<Order::HeaderV>>>> {
		Arc::downgrade(&self.unflushed_entries.entries)
	}

	/// Return strong reference to current set of entries.
	pub fn unflushed_entries_ref(&self) -> &[Arc<InMemoryEntry<Order::HeaderV>>] {
		&self.unflushed_entries.entries
	}

	/// Return weak reference to current set of entries. The caller may clone and
	/// hold the reference, but it is better to hold weak reference instead and
	/// upgrade only when required. In this case, the underlying `Vec<InMemoryEntry>`
	/// and `EntriesState`` won't be cloned during updates.
	///
	/// Flushed entries are supposed to be used in e.g. sync where we need to be sure
	/// that we're using persistent version of entries.
	pub fn flushed_entries(&self) -> Weak<InMemoryEntries<Order::HeaderV>> {
		Arc::downgrade(&self.flushed_entries)
	}

	/// Return strong reference to current flushed set of entries.
	pub fn flushed_entries_ref(&self) -> &Arc<InMemoryEntries<Order::HeaderV>> {
		&self.flushed_entries
	}

	/// Insert new entry into the storage.
	pub fn insert<BodyV>(
		&mut self,
		entry: Entry<Unencrypted<Order::HeaderV>, Unencrypted<BodyV>>,
	) -> Result<EntryIndex, Error>
	where
		BodyV: Encode + Zeroize,
	{
		self.unflushed_entries.insert(entry)
	}

	/// Update existing entry in the storage.
	pub fn update<BodyV>(
		&mut self,
		old_entry: Arc<InMemoryEntry<Order::HeaderV>>,
		entry: Entry<Unencrypted<Order::HeaderV>, Unencrypted<BodyV>>,
	) -> Result<(), Error>
	where
		BodyV: Encode + Zeroize,
	{
		self.unflushed_entries.update(old_entry, entry)
	}

	/// Modify unflushed entries in transaction - either transaction succeeds, or unflushed
	/// entries are reverted back to the original state.
	pub fn apply_batch(
		&mut self,
		batch: impl IntoIterator<Item = EntriesBatchOp<Order::HeaderV>>,
	) -> Result<(), Error> {
		fn do_apply_batch<Order: EntriesOrder>(
			unflushed: &mut UnflushedEntries<Order>,
			batch: impl IntoIterator<Item = EntriesBatchOp<Order::HeaderV>>,
		) -> Result<(), Error>
		where
			Order::HeaderV: Clone + Decode<()> + Encode + Zeroize,
		{
			for batch_op in batch {
				match batch_op {
					EntriesBatchOp::InsertEntry { entry } => {
						unflushed.insert_encrypted(entry)?;
					}
					EntriesBatchOp::UpdateEntry { old_entry, entry } => {
						unflushed.update_encrypted(old_entry, entry)?;
					}
				}
			}

			Ok(())
		}

		// this is a heavy operation, but we're getting consistency in return
		let original_entries = self.unflushed_entries.entries.clone();

		let result = do_apply_batch(&mut self.unflushed_entries, batch);
		if result.is_err() {
			self.unflushed_entries.entries = original_entries;
		}

		result
	}

	/// Flush all current entries to disk.
	pub fn flush(&mut self) -> Result<(), Error> {
		self.storage.write(|mut writer| {
			// write number of entries
			let n_entries = self.unflushed_entries.entries.len() as u16;
			write_plain(&mut writer, n_entries).context("writing entries")?;

			// this could lead to heavy clone operation if any other component holds reference
			// to `self.state`
			let new_flushed_entries = Arc::make_mut(&mut self.flushed_entries);
			let mut batch_op = new_flushed_entries.state.batch_op();
			for (index, entry) in self.unflushed_entries.entries.iter().enumerate() {
				// write secret to the storage
				let entry_hash = entry.hash();
				write_secret(
					&self.master,
					&mut writer,
					HashedEncrypted {
						hash: entry_hash,
						encrypted: entry.entry(),
					},
				)
				.context("writing entries")?;

				// and update state if required
				let index: EntryIndex = index
					.try_into()
					.expect("there's always less than u16::MAX entries in the storage; qed");
				if Some(&entry.hash()) != batch_op.entry_hash(index) {
					tracing::debug!("entry {:?} has new hash: {:?}", index, entry_hash);
					batch_op.change(index, entry_hash)?;
				}
			}

			// we've done with updating => complete batch op and compute new l0 hash
			let batch_op = batch_op.complete();
			// prepare metadata
			let metadata = Metadata {
				l0_hash: batch_op.l0_hash(),
			};
			// write metadata
			write_secret(&self.master, &mut writer, &metadata).context("writing metadata")?;

			// no more errors starting from this line

			// no more storage errors => we can commit state operation
			batch_op.commit();
			// and clone unflushed entries to flushed
			new_flushed_entries.entries = self.unflushed_entries.entries.clone();

			Ok(())
		})
	}

	/// Construct [Entries] from given reader.
	fn from_reader(
		master: Arc<MasterPassword>,
		mut reader: impl Read,
	) -> Result<InMemoryEntries<Order::HeaderV>, Error> {
		// read entries, one by one to avoid additional encoding while computing entry hash
		let n_entries: u16 = read_plain(&mut reader).context("reading entries")?;
		let mut state = EntriesState::with_capacity(n_entries as usize);
		let mut entries = Vec::with_capacity(n_entries as usize);
		let mut batch_op = state.batch_op();
		for entry_index in 0..n_entries {
			let entry_index: EntryIndex = entry_index.into();
			let hashed_entry: HashedEncrypted<Entry<Unencrypted<Order::HeaderV>, Encrypted>> =
				read_secret(&master, &mut reader).context("reading entries")?;
			let entry =
				master.create_from_plain_header(hashed_entry.encrypted, hashed_entry.hash)?;
			entries.push(Arc::new(entry));
			batch_op.change(entry_index, hashed_entry.hash)?;
		}

		// we've done reading entries => complete batch op
		let batch_op = batch_op.complete();
		// read metadata
		let metadata: Metadata = read_secret(&master, &mut reader).context("reading metadata")?;
		// verify L0 hash. It protects us from attacks where some external entry may rewrite
		// all our encrypted entries with single encrypted entry. It won't protect us from e.g.
		// reverting to any previous entries version, though.
		if batch_op.l0_hash() != metadata.l0_hash {
			return Err(Error::from(ErrorKind::MetadataHashMismatch {
				expected: batch_op.l0_hash(),
				actual: metadata.l0_hash,
			}));
		}
		// commit batch op
		batch_op.commit();

		Ok(InMemoryEntries {
			entries: Arc::new(entries),
			state,
		})
	}
}

impl<Order: EntriesOrder> UnflushedEntries<Order>
where
	Order::HeaderV: Decode<()> + Encode + Zeroize,
{
	/// Insert new encrypted entry into the storage.
	pub fn insert_encrypted(
		&mut self,
		entry: Arc<InMemoryEntry<Order::HeaderV>>,
	) -> Result<EntryIndex, Error> {
		// check that we're under limit
		if self.entries.len() >= u16::MAX as usize {
			return Err(Error::from(ErrorKind::TooManyEntries));
		}

		// find entry index and make sure that there's no other equal entry
		let Err(index) = self
			.entries
			.binary_search_by(|existing_entry| Order::cmp(existing_entry.entry(), entry.entry()))
		else {
			return Err(Error::from(ErrorKind::TryingToInsertDuplicateEntry));
		};

		// this could lead to heavy clone operation if any other component holds strong
		// reference to `self.entries`
		// yet it could lead to reallocation + memmove, but we expect updates to be rare
		Arc::make_mut(&mut self.entries).insert(index, entry);

		Ok(index
			.try_into()
			.expect("we've checked that there are less than u16::MAX entries in the storage; qed"))
	}

	/// Insert new entry into the storage.
	pub fn insert<BodyV>(
		&mut self,
		entry: Entry<Unencrypted<Order::HeaderV>, Unencrypted<BodyV>>,
	) -> Result<EntryIndex, Error>
	where
		BodyV: Encode + Zeroize,
	{
		self.insert_encrypted(Arc::new(self.master.create_from_plain_entry(entry)?))
	}

	/// Update existing entry in the storage.
	pub fn update_encrypted(
		&mut self,
		old_entry: Arc<InMemoryEntry<Order::HeaderV>>,
		entry: Arc<InMemoryEntry<Order::HeaderV>>,
	) -> Result<(), Error> {
		// make sure entry exists in the storage
		let Ok(index) = self
			.entries
			.binary_search_by(|existing_entry| Order::cmp(existing_entry.entry(), entry.entry()))
		else {
			return Err(Error::from(ErrorKind::TryingToUpdateNonExistentEntry));
		};
		// make sure entry was not updated since user has seen it
		let current_entry = &self.entries[index];
		if !Arc::ptr_eq(&old_entry, current_entry) {
			return Err(Error::from(ErrorKind::TryingToUpdateUpdatedEntry));
		}

		// this could lead to heavy clone operation if any other component holds reference
		// to `self.entries`
		Arc::make_mut(&mut self.entries)[index] = entry;

		Ok(())
	}

	/// Update existing entry in the storage.
	pub fn update<BodyV>(
		&mut self,
		old_entry: Arc<InMemoryEntry<Order::HeaderV>>,
		entry: Entry<Unencrypted<Order::HeaderV>, Unencrypted<BodyV>>,
	) -> Result<(), Error>
	where
		BodyV: Encode + Zeroize,
	{
		self.update_encrypted(
			old_entry,
			Arc::new(self.master.create_from_plain_entry(entry)?),
		)
	}
}

/// Read and decode plain value from `reader`.
fn read_plain<T: Decode<()>>(reader: &mut impl Read) -> Result<T, Error> {
	bincode::decode_from_std_read(reader, bincode_config())
		.map_err(|e| ErrorKind::DecodeError(e).into())
}

/// Read and decode secret value from the `reader`. `secret_hash` is set to hash of decrypted
/// and encoded value.
fn read_secret<T: Decode<()>>(master: &MasterPassword, reader: &mut impl Read) -> Result<T, Error> {
	let config = bincode_config();

	// read and decode `EncryptedBody` from the `reader`
	let secret: Encrypted = bincode::decode_from_std_read(reader, config)
		.map_err(|e| Error::from(ErrorKind::DecodeError(e)))?;

	// decrypt secret from `EncryptedBody`
	let secret = master.decrypt(&secret)?;

	// and decode `value` from decrypted `secret`
	bincode::decode_from_reader(SliceReader::new(secret.expose_secret()), config)
		.map_err(|e| ErrorKind::DecodeError(e).into())
}

/// Write plain `value` into `writer`.
fn write_plain<T: Encode>(writer: &mut impl Write, value: T) -> Result<(), Error> {
	bincode::encode_into_std_write(value, writer, bincode_config())
		.map_err(|e| Error::from(ErrorKind::EncodeError(e)))
		.map(drop)
}

/// Encrypt `secret` and write encrypted value to the `writer`. Hash of encoded (but
/// not encrypted) value is written to the `secret_hash` when it is `Some(_)`.
fn write_secret<T: Encode>(
	master: &MasterPassword,
	writer: &mut impl Write,
	secret: T,
) -> Result<(), Error> {
	let config = bincode_config();

	// encode `secret`
	let secret = bincode::encode_to_vec(secret, bincode_config())
		.map_err(|e| Error::from(ErrorKind::EncodeError(e)))?;

	// encrypt encoded `secret`
	let secret = master.encrypt(secret.into())?;

	// write encrypred `secret` to the writer
	bincode::encode_into_std_write(secret, writer, config)
		.map_err(|e| Error::from(ErrorKind::EncodeError(e)))?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::io::Seek;

	use super::*;
	use crate::test_utils::*;

	use assert_matches::assert_matches;

	#[tokio::test]
	async fn entries_are_empty_when_storage_file_is_empty() {
		with_tempdir(|path| async move {
			let entries = Entries::<TestOrder>::new(&path, master()).unwrap();
			assert!(entries.unflushed_entries_ref().is_empty());
			assert!(entries.flushed_entries_ref().entries.is_empty());
			assert!(
				entries
					.flushed_entries_ref()
					.state
					.entry_hashes()
					.is_empty()
			);
		})
		.await;
	}

	#[tokio::test]
	async fn entries_read_fails_with_other_password() {
		with_tempdir(|path| async move {
			{
				let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();
				entries.insert(plain_entry(0)).unwrap();
				entries.flush().unwrap();
			}

			// when trying to read with other password => error
			let other_master =
				Arc::new(MasterPassword::from_password_secret("other-password".into()).unwrap());
			assert!(Entries::<TestOrder>::new(&path, other_master).is_err());
		})
		.await;
	}

	#[tokio::test]
	async fn entries_are_not_flushed_until_explicit_flush_call() {
		with_tempdir(|path| async move {
			{
				let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();
				entries.insert(plain_entry(0)).unwrap();
			}

			// even though we've added entry before, it isn't here after reload
			let entries = Entries::<TestOrder>::new(&path, master()).unwrap();
			assert!(entries.unflushed_entries_ref().is_empty());
			assert!(entries.flushed_entries_ref().entries.is_empty());
			assert!(
				entries
					.flushed_entries_ref()
					.state
					.entry_hashes()
					.is_empty()
			);
		})
		.await;
	}

	#[tokio::test]
	async fn entry_insert_fails_if_this_entry_already_exist() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// insert entry with key=0
			entries.insert(plain_entry(0)).unwrap();

			// try to insert same entry again
			assert_matches!(
				entries.insert(plain_entry(0)),
				Err(Error::Base(ErrorKind::TryingToInsertDuplicateEntry))
			);
		})
		.await;
	}

	#[tokio::test]
	async fn entry_update_fails_if_entry_has_been_updated() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// add entry#0
			entries.insert(plain_entry_with_key(0, 0)).unwrap();

			// update entry#0
			let old_entry = entries.unflushed_entries_ref()[0].clone();
			entries
				.update(old_entry.clone(), plain_entry_with_key(0, 1))
				.unwrap();

			// try to update it again using old reference => error
			assert_matches!(
				entries.update(old_entry, plain_entry_with_key(0, 2)),
				Err(Error::Base(ErrorKind::TryingToUpdateUpdatedEntry))
			);
		})
		.await;
	}

	#[tokio::test]
	async fn entry_update_fails_if_entry_does_not_exist() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// try to update it again using old reference => error
			assert_matches!(
				entries.update(in_memory_entry_with_key(0, 0), plain_entry_with_key(0, 2)),
				Err(Error::Base(ErrorKind::TryingToUpdateNonExistentEntry))
			);
		})
		.await;
	}

	#[tokio::test]
	async fn entry_may_be_updated() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			entries.insert(plain_entry_with_key(0, 100)).unwrap();
			let old_entry = entries.unflushed_entries_ref()[0].clone();
			let old_hash = old_entry.hash();

			entries
				.update(old_entry, plain_entry_with_key(0, 200))
				.unwrap();
			let hash2 = entries.unflushed_entries_ref()[0].hash();

			assert_ne!(old_hash, hash2);
		})
		.await;
	}

	#[tokio::test]
	async fn batch_fails_when_updating_missing_entry() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();
			let batch = vec![EntriesBatchOp::UpdateEntry {
				old_entry: in_memory_entry(0),
				entry: in_memory_entry(0),
			}];
			assert_matches!(
				entries.apply_batch(batch).map_err(Error::into_inner),
				Err(ErrorKind::TryingToUpdateNonExistentEntry)
			);
		})
		.await;
	}

	#[tokio::test]
	async fn batch_fails_when_entry_is_already_updated() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// add entry#0
			entries.insert(plain_entry_with_key(0, 0)).unwrap();

			// prepare batch that updates entry#0
			let batch = vec![EntriesBatchOp::UpdateEntry {
				old_entry: entries.unflushed_entries_ref()[0].clone(),
				entry: in_memory_entry_with_key(0, 1),
			}];

			// update entry#0 in storage
			entries
				.update(
					entries.unflushed_entries_ref()[0].clone(),
					plain_entry_with_key(0, 2),
				)
				.unwrap();

			// try to apply batch - it fails
			assert_matches!(
				entries.apply_batch(batch).map_err(Error::into_inner),
				Err(ErrorKind::TryingToUpdateUpdatedEntry)
			);
		})
		.await;
	}

	#[tokio::test]
	async fn whole_batch_is_reverted_when_it_fails() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// add entry#0
			entries.insert(plain_entry_with_key(0, 0)).unwrap();
			let entry0_hash = entries.unflushed_entries_ref()[0].hash();

			// prepare batch with 100 new entries
			let mut batch = Vec::with_capacity(101);
			for index in 1..=100 {
				batch.push(EntriesBatchOp::InsertEntry {
					entry: in_memory_entry(index as _),
				});
			}
			// ..and single update op that will fail
			let batch = vec![EntriesBatchOp::UpdateEntry {
				old_entry: in_memory_entry_with_key(0, 0),
				entry: in_memory_entry_with_key(0, 1),
			}];

			// try to apply batch - it fails
			assert_matches!(
				entries.apply_batch(batch).map_err(Error::into_inner),
				Err(ErrorKind::TryingToUpdateUpdatedEntry)
			);

			// and entries are untouched
			assert_eq!(entries.unflushed_entries_ref().len(), 1);
			assert_eq!(entries.unflushed_entries_ref()[0].hash(), entry0_hash);
		})
		.await;
	}

	#[tokio::test]
	async fn apply_batch_works() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// add entry#0
			entries.insert(plain_entry(0)).unwrap();

			// create batch that: adds entry#1 and updates entry#0
			let entry0_old = entries.unflushed_entries_ref()[0].clone();
			let entry0_new = in_memory_entry_with_key(0, 0);
			let entry0_hash = entry0_new.hash();
			let entry1_new = in_memory_entry_with_key(1, 1);
			let entry1_hash = entry1_new.hash();
			let batch = vec![
				EntriesBatchOp::InsertEntry { entry: entry1_new },
				EntriesBatchOp::UpdateEntry {
					old_entry: entry0_old,
					entry: entry0_new,
				},
			];

			// apply batch
			entries.apply_batch(batch).unwrap();

			// check that entries have been updated
			assert_eq!(entries.unflushed_entries_ref()[0].hash(), entry0_hash);
			assert_eq!(entries.unflushed_entries_ref()[1].hash(), entry1_hash);
		})
		.await;
	}

	#[tokio::test]
	async fn unflushed_weak_ref_is_none_after_entries_are_modified() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// when entries are created, flushed and unflushed entries share the same pointer
			assert!(Arc::ptr_eq(
				&entries.flushed_entries.entries,
				&entries.unflushed_entries.entries
			));

			// let's split flushed and unflushed ptrs
			entries.insert(plain_entry(0)).unwrap();

			// now flushed and unflushed are different
			assert!(!Arc::ptr_eq(
				&entries.flushed_entries.entries,
				&entries.unflushed_entries.entries
			));

			// get unflushed entries reference
			let unflushed_ref = entries.unflushed_entries();
			assert!(unflushed_ref.upgrade().is_some());

			// add one more entry
			entries.insert(plain_entry(1)).unwrap();

			// weak ref is spoiled
			assert!(unflushed_ref.upgrade().is_none());
		})
		.await;
	}

	#[tokio::test]
	async fn flushed_weak_ref_is_none_after_entries_are_modified() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();

			// get unflushed entries reference
			let flushed_ref = entries.flushed_entries();
			assert!(flushed_ref.upgrade().is_some());

			// add entry#0
			entries.insert(plain_entry(0)).unwrap();

			// flushed_ref is still Ok
			assert!(flushed_ref.upgrade().is_some());

			// but after we call flush
			entries.flush().unwrap();
			// weak ref is spoiled
			assert!(flushed_ref.upgrade().is_none());
		})
		.await;
	}

	#[tokio::test]
	async fn flush_makes_unflushed_entries_persistent() {
		with_tempdir(|path| async move {
			let entry0_hash = {
				// add entry and flush
				let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();
				entries.insert(plain_entry(0)).unwrap();
				entries.flush().unwrap();

				// both flushed and unflushed store the same pointer
				assert!(Arc::ptr_eq(
					&entries.flushed_entries.entries,
					&entries.unflushed_entries.entries
				));

				entries.unflushed_entries_ref()[0].hash()
			};

			// since we've flushe before, it is here after reload
			let entries = Entries::<TestOrder>::new(&path, master()).unwrap();
			assert_eq!(entries.unflushed_entries_ref()[0].hash(), entry0_hash);
		})
		.await;
	}

	#[tokio::test]
	async fn entry_add_fails_if_there_are_too_many_entries() {
		with_tempdir(|path| async move {
			let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();
			for i in 0..u16::MAX {
				entries.insert(plain_entry_with_key(i as _, 0)).unwrap();
			}
			assert_eq!(entries.unflushed_entries.entries.len(), u16::MAX as _);

			let mut new_entry = plain_entry_with_key(0, 0);
			new_entry.set_key("too-many-entries".into());

			assert_matches!(
				entries.insert(new_entry),
				Err(Error::Base(ErrorKind::TooManyEntries))
			);
		})
		.await;
	}

	#[tokio::test]
	async fn fail_to_open_when_metadata_hash_mismatch() {
		with_tempdir(|path| async move {
			{
				// add entry and flush
				let mut entries = Entries::<TestOrder>::new(&path, master()).unwrap();
				entries.insert(plain_entry(0)).unwrap();
				entries.flush().unwrap();
			}

			// so now we need to replace correct metadata with invalid
			{
				let invalid = Metadata::default();
				let invalid_enc = master()
					.encrypt(
						bincode::encode_to_vec(&invalid, bincode_config())
							.unwrap()
							.into(),
					)
					.unwrap();
				let invalid_enc_encoded =
					bincode::encode_to_vec(&invalid_enc, bincode_config()).unwrap();

				let mut file = std::fs::File::options()
					.read(true)
					.write(true)
					.open(&path)
					.unwrap();
				let file_len = file.metadata().unwrap().len();
				file.seek(std::io::SeekFrom::Start(
					file_len - invalid_enc_encoded.len() as u64,
				))
				.unwrap();
				file.write_all(&invalid_enc_encoded).unwrap();
			}

			assert_matches!(
				Entries::<TestOrder>::new(&path, master()).unwrap_err(),
				Error::Base(ErrorKind::MetadataHashMismatch { .. })
			);
		})
		.await;
	}
}
