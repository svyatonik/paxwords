use super::{
	InMemoryEntry,
	in_memory_entry::{decrypt_and_decode, encode_and_encrypt},
};
use crate::{
	Error, MasterPassword,
	types::{Encrypted, Entry, Hash, Unencrypted},
};

use bincode::{Decode, Encode};
use std::sync::Arc;
use thiserror_context::Context;
use zeroize::Zeroize;

/// Something that may hash + encrypt plain entries and produce [InMemoryEntry].
pub trait EntryEncrypter<HeaderV: Decode<()> + Encode + Zeroize> {
	/// Produce [InMemoryEntry] from pre-encrypted entry.
	fn create_from_encrypted_entry<BodyV: Decode<()> + Encode + Zeroize>(
		&self,
		entry: Entry<Encrypted, Encrypted>,
	) -> Result<InMemoryEntry<HeaderV>, Error>;

	/// Produce [InMemoryEntry] from entry with pre-encrypted body.
	fn create_from_plain_header(
		&self,
		entry: Entry<Unencrypted<HeaderV>, Encrypted>,
		hash: Hash,
	) -> Result<InMemoryEntry<HeaderV>, Error>;

	/// Produce [InMemoryEntry] from plain entry.
	fn create_from_plain_entry<BodyV: Encode + Zeroize>(
		&self,
		entry: Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>,
	) -> Result<InMemoryEntry<HeaderV>, Error>;
}

impl<HeaderV: Decode<()> + Encode + Zeroize> EntryEncrypter<HeaderV> for Arc<MasterPassword> {
	fn create_from_encrypted_entry<BodyV: Decode<()> + Encode + Zeroize>(
		&self,
		entry: Entry<Encrypted, Encrypted>,
	) -> Result<InMemoryEntry<HeaderV>, Error> {
		self.create_from_plain_entry(Entry {
			header: decrypt_and_decode::<Unencrypted<HeaderV>>(self, &entry.header)
				.context("decrypting header")?,
			body: decrypt_and_decode::<Unencrypted<BodyV>>(self, &entry.body)
				.context("decrypting body")?,
		})
	}

	fn create_from_plain_header(
		&self,
		entry: Entry<Unencrypted<HeaderV>, Encrypted>,
		hash: Hash,
	) -> Result<InMemoryEntry<HeaderV>, Error> {
		Ok(InMemoryEntry::new(self.clone(), hash, entry))
	}

	fn create_from_plain_entry<BodyV: Encode + Zeroize>(
		&self,
		entry: Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>,
	) -> Result<InMemoryEntry<HeaderV>, Error> {
		let hash = entry.hash()?;
		let entry = Entry {
			header: entry.header,
			body: encode_and_encrypt(self.as_ref(), entry.body).context("encrypting body")?,
		};
		Ok(InMemoryEntry::new(self.clone(), hash, entry))
	}
}
