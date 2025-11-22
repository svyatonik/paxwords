//! Crate that provides basic `paxwords` functionality, including:
//!
//! - [MasterPassword]: used to encrypt everything;
//!
//! - [Entries]: a list of secrets, managed by paxwords and backed by the local file storage;
//!
//! - all required basic types: [Entry], [Header], [Id], [PlainBody] and [Timestamp].

#![deny(missing_docs)]

pub use crypto::{EncryptionKey, MasterPassword};
pub use entries::{Entries, EntriesBatchOp, EntryEncrypter, InMemoryEntries, InMemoryEntry};
pub use sync::{
	EntriesState, LastChanceDecision, LocalPeer, MergeAlgorithm, Peer, PeerState,
	apply_remote_entries, find_differences, retrieve_entries,
};
pub use types::{
	Encrypted, EntriesOrder, Entry, EntryIndex, Hash, HashHalf, PlainMap, Secret, Unencrypted,
};

pub use secrecy;

use bincode::error::DecodeError;
use bincode::error::EncodeError;
use std::io::Error as IoError;
use thiserror::Error;

pub mod utils;

mod crypto;
mod entries;
mod sync;
mod types;

/// A paxwordmg error.
#[derive(Debug, Error)]
pub enum ErrorKind {
	/// Error generating random value.
	#[error("error generating random value: {0}")]
	RandomGenerationFailed(rand_core::OsError),
	/// Key derivation error.
	#[error("error deriving key: {0}")]
	KeyDerivationFailed(hkdf::InvalidLength),
	/// Secret encryption has failed with some error.
	#[error("error encrypting secret: {0}")]
	EncryptionFailed(chacha20poly1305::Error),
	/// Secret decryption has failed with some error.
	#[error("error decrypting secret: {0}")]
	DecryptionFailed(chacha20poly1305::Error),
	/// Failed to recover master key.
	#[error("error recovering master key")]
	MasterKeyRecoveryFailed,

	/// Invalid entry index.
	#[error("entry index is invalid: {0:?}")]
	InvalidEntryIndex(EntryIndex),
	/// There are too many entries in the storage.
	#[error("too many entries in the storage")]
	TooManyEntries,
	/// L0 hash from metadata doesn't match actual L0 hash.
	#[error("L0 hash mismatch: expected={expected} actual={actual}")]
	MetadataHashMismatch {
		/// Hash stored in metadata.
		expected: Hash,
		/// Actual entries hash.
		actual: Hash,
	},

	/// Encoding has failed.
	#[error("encoding error: {0}")]
	EncodeError(EncodeError),
	/// Decoding has failed.
	#[error("decoding error: {0}")]
	DecodeError(DecodeError),

	/// Trying to insert duplicate entry into the storage.
	#[error("trying to insert duplicate entry into the storage")]
	TryingToInsertDuplicateEntry,
	/// Trying to update entry that doesn't exist in the storage.
	#[error("trying to update entry that doesn't exist in the storage")]
	TryingToUpdateNonExistentEntry,
	/// Trying to update entry that has been updated by someone else.
	#[error("trying to update entry that has been updated by someone else")]
	TryingToUpdateUpdatedEntry,

	/// A communication with sync peer has failed.
	#[error("failed to communicate with peer: {0}")]
	PeerCommunicationError(IoError),
	/// A state is temporary unavailable.
	#[error("a state is temporary unavailable")]
	StateUnavailable,

	/// Storage open error.
	#[error("failed to open storage: {0}")]
	StorageOpenFailed(IoError),
	/// Storage lock error.
	#[error("failed to lock storage: {0}")]
	StorageLockFailed(IoError),
	/// Storage read error.
	#[error("failed to read from storage: {0}")]
	StorageReadFailed(IoError),
	/// Storage write error.
	#[error("failed to write to storage: {0}")]
	StorageWriteFailed(IoError),
}

pub use error::*;

#[allow(missing_docs)]
mod error {
	use thiserror_context::{Context, impl_context};
	impl_context!(Error(super::ErrorKind));
}

#[cfg(test)]
mod test_utils {
	use super::{entries::EntryEncrypter, *};
	use std::{
		path::PathBuf,
		sync::{
			Arc,
			atomic::{AtomicBool, AtomicU16, Ordering},
		},
	};
	use tempdir::TempDir;

	pub const KEY: &str = "header_key";
	pub const VALUE: &str = "'value_value";

	pub trait TestHeader {
		fn key(&self) -> String;
		fn set_key(&mut self, key: String);
	}

	pub trait TestBody {
		fn value(&self) -> u64;
		fn set_value(&mut self, version: u64);
	}

	impl<Body> TestHeader for Entry<Unencrypted<String>, Body> {
		fn key(&self) -> String {
			self.header.get(KEY).cloned().unwrap_or_default()
		}

		fn set_key(&mut self, key: String) {
			self.header.insert(KEY.into(), key);
		}
	}

	impl<Header> TestBody for Entry<Header, Unencrypted<u64>> {
		fn value(&self) -> u64 {
			self.body.get(VALUE).cloned().unwrap_or_default()
		}

		fn set_value(&mut self, version: u64) {
			self.body.insert(VALUE.into(), version);
		}
	}

	pub type PlainEntry = Entry<Unencrypted<String>, Unencrypted<u64>>;

	pub static LAST_CHANCE_MERGE_INTO: AtomicU16 = AtomicU16::new(u16::MAX);
	pub static LAST_CHANCE_CALLED: AtomicBool = AtomicBool::new(false);

	pub struct TestMergeAlgorithm;
	pub type TestOrder = TestMergeAlgorithm;

	impl EntriesOrder for TestMergeAlgorithm {
		type HeaderV = String;

		fn cmp(
			left: &Entry<Unencrypted<Self::HeaderV>, Encrypted>,
			right: &Entry<Unencrypted<Self::HeaderV>, Encrypted>,
		) -> std::cmp::Ordering {
			left.key().cmp(&right.key())
		}
	}

	impl MergeAlgorithm<String, u64> for TestMergeAlgorithm {
		fn merge(
			into: InMemoryEntry<String>,
			what: &InMemoryEntry<String>,
		) -> Result<Entry<Unencrypted<String>, Unencrypted<u64>>, Error> {
			let mut into_plain = into.decrypt::<u64>().unwrap();
			let what_plain = what.decrypt::<u64>().unwrap();
			into_plain.set_value(into_plain.value() + what_plain.value());
			Ok(into_plain)
		}

		fn last_chance(_remote_entry: &InMemoryEntry<String>) -> LastChanceDecision {
			// remember that last_chance has been called
			LAST_CHANCE_CALLED.store(true, Ordering::SeqCst);
			// decide what to do
			let merge_with = LAST_CHANCE_MERGE_INTO.load(Ordering::SeqCst);
			if merge_with == 0 {
				return LastChanceDecision::Discard;
			}

			LastChanceDecision::MergeInto {
				merge_with: merge_with.into(),
			}
		}
	}

	pub fn master() -> Arc<MasterPassword> {
		use parking_lot::Mutex;

		static MASTER: Mutex<Option<Arc<MasterPassword>>> = Mutex::new(None);

		let mut guard = MASTER.lock();
		if guard.is_none() {
			*guard = Some(Arc::new(
				MasterPassword::from_password_secret("password".into()).unwrap(),
			));
		}
		guard.as_ref().cloned().unwrap()
	}

	pub fn plain_entry(value: u64) -> PlainEntry {
		plain_entry_with_key(value, value)
	}

	pub fn plain_entry_with_key(key: u64, value: u64) -> PlainEntry {
		let mut entry = PlainEntry::default();
		entry.set_key(format!("key-{key}"));
		entry.set_value(value);
		entry
	}

	pub fn in_memory_entry(value: u64) -> Arc<InMemoryEntry<String>> {
		Arc::new(
			master()
				.create_from_plain_entry(plain_entry(value))
				.unwrap(),
		)
	}

	pub fn in_memory_entry_with_key(key: u64, value: u64) -> Arc<InMemoryEntry<String>> {
		let mut entry = plain_entry(key);
		entry.set_value(value);
		Arc::new(master().create_from_plain_entry(entry).unwrap())
	}

	pub async fn with_tempdir<F: Future<Output = ()>>(f: impl FnOnce(PathBuf) -> F) {
		let tempdir = TempDir::new("paxwords-tests").unwrap();
		let mut path: PathBuf = tempdir.path().into();
		path.push("paxwords");
		f(path).await;
	}
}
