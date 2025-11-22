use bincode::{Decode, Encode};
use secrecy::ExposeSecret;
use std::sync::Arc;
use thiserror_context::Context;

use crate::{
	Error, ErrorKind, MasterPassword,
	sync::EntriesState,
	types::{Encrypted, Entry, Hash, Unencrypted, bincode_config},
};

/// Flushed entries as they're stored in RAM.
#[derive(Clone)]
pub struct InMemoryEntries<HeaderV> {
	/// A set of flushed in-memory entries.
	///
	/// Why `Arc` for the whole `Vec`? Because we maintain two sets of entries - flushed
	/// and unflushed. They're identical until any changes are made to the unflushed set
	/// (which is a rare op).
	///
	/// Why `Arc` for the `InMemoryEntry`? Even after changes are made to some entry and
	/// until it is flushed to the disk, most of entries in two sets are still the same.
	/// And we do not want to clone potentially large entries.
	pub entries: Arc<Vec<Arc<InMemoryEntry<HeaderV>>>>,
	/// A view of entries state.
	pub state: EntriesState,
}

impl<HeaderV> Default for InMemoryEntries<HeaderV> {
	fn default() -> Self {
		Self {
			entries: Arc::new(Vec::new()),
			state: Default::default(),
		}
	}
}

/// Entry as it is stored in RAM. Its header is stored in unencrypted form and its body is
/// encrypted.
#[derive(Clone)]
pub struct InMemoryEntry<HeaderV> {
	/// Master password.
	master: Arc<MasterPassword>,
	/// Underlying entry hash.
	hash: Hash,
	/// Underlying entry with encrypted header. `None` if entry has been removed.
	entry: Entry<Unencrypted<HeaderV>, Encrypted>,
}

impl<HeaderV> std::fmt::Debug for InMemoryEntry<HeaderV> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "InMemoryEntry({})", self.hash)
	}
}

impl<HeaderV> InMemoryEntry<HeaderV> {
	/// Create new 'dirty' entry.
	pub fn new(
		master: Arc<MasterPassword>,
		hash: Hash,
		entry: Entry<Unencrypted<HeaderV>, Encrypted>,
	) -> Self {
		Self {
			master,
			hash,
			entry,
		}
	}

	/// Return underlying entry hash.
	pub fn hash(&self) -> Hash {
		self.hash
	}

	/// Return underlying encrypted entry reference.
	pub fn entry(&self) -> &Entry<Unencrypted<HeaderV>, Encrypted> {
		&self.entry
	}

	/// Return entry with encrypted header and body.
	pub fn encrypted_entry(&self) -> Result<Entry<Encrypted, Encrypted>, Error>
	where
		HeaderV: Clone + Encode,
	{
		Ok(Entry {
			header: encode_and_encrypt(&self.master, &self.entry.header)?,
			body: self.entry.body.clone(),
		})
	}

	/// Return entry with decrypted header and body.
	pub fn decrypt<BodyV: Decode<()>>(
		&self,
	) -> Result<Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>, Error>
	where
		HeaderV: Clone,
	{
		let body_plain =
			decrypt_and_decode(&self.master, &self.entry.body).context("decrypting body")?;
		Ok(self.entry.clone().switch_body(body_plain))
	}
}

/// Encode and encrypt entry header or body.
pub(super) fn encode_and_encrypt(
	master: &MasterPassword,
	plain: impl Encode,
) -> Result<Encrypted, Error> {
	let plain_encoded = bincode::encode_to_vec(plain, bincode_config())
		.map_err(|e| Error::from(ErrorKind::EncodeError(e)))?;
	master.encrypt(plain_encoded.into())
}

/// Decrypt and decode entry header or body.
pub(super) fn decrypt_and_decode<T>(
	master: &MasterPassword,
	encrypted: &Encrypted,
) -> Result<T, Error>
where
	T: Decode<()>,
{
	let encoded = master.decrypt(encrypted)?;
	bincode::decode_from_slice(encoded.expose_secret(), bincode_config())
		.map(|(body, _)| body)
		.map_err(|e| Error::from(ErrorKind::DecodeError(e)))
}
