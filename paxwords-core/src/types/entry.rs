use super::SecretWithAutorization;
use crate::{Error, ErrorKind, types::bincode_config};

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{collections::HashMap, fmt};
use zeroize::Zeroize;

/// Entry index is u16, which means that we may store at most 65_536 entries.
#[derive(
	Clone,
	Copy,
	Debug,
	Decode,
	Deserialize,
	Default,
	Encode,
	Eq,
	Ord,
	PartialEq,
	PartialOrd,
	Serialize,
)]
pub struct EntryIndex(u16);

impl EntryIndex {
	/// Return index, increased by one.
	pub fn next_index(&self) -> Option<EntryIndex> {
		self.0.checked_add(1).map(Self)
	}
}

impl From<u16> for EntryIndex {
	fn from(value: u16) -> Self {
		Self(value)
	}
}

impl From<EntryIndex> for u16 {
	fn from(value: EntryIndex) -> Self {
		value.0
	}
}

impl TryFrom<usize> for EntryIndex {
	type Error = std::num::TryFromIntError;

	fn try_from(value: usize) -> Result<Self, Self::Error> {
		value.try_into().map(Self)
	}
}

impl From<EntryIndex> for usize {
	fn from(value: EntryIndex) -> Self {
		value.0 as _
	}
}

/// Hash (sha256) of the encoded [Entry]. It is usually computed for entries
/// with encrypted body (i.e. [Entry<SecretWithAutorization>]).
#[derive(Clone, Copy, Decode, Deserialize, Default, Encode, Eq, Serialize, Zeroize)]
pub struct Hash(pub [u8; 32]);

impl fmt::Debug for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Hash({})", hex::encode(self.0))
	}
}

impl fmt::Display for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", hex::encode(self.0))
	}
}

impl PartialEq for Hash {
	fn eq(&self, other: &Self) -> bool {
		subtle::ConstantTimeEq::ct_eq(&self.0[..], &other.0[..]).into()
	}
}

impl Hash {
	/// Compute hash of raw data.
	pub fn hash_raw(data: &[u8]) -> Hash {
		Hash(sha2::Sha256::digest(data).into())
	}

	/// Return lower half of this hash. Since we use hashes in secure environment
	/// only (both peers trust each other) and we only use them to compare entries,
	/// it should be enough to compare just 16 bytes of the hash.
	pub fn half(&self) -> HashHalf {
		let mut half = [0u8; 16];
		half.copy_from_slice(&self.0[..16]);
		HashHalf(half)
	}
}

/// Lower half of [Hash]. Since we assume that all inter-peer communications
/// happen over safe channels and our peers are not adversarial, we can use
/// half of the [Hash] to identify entries from the storage.
#[derive(Clone, Copy, Decode, Deserialize, Default, Encode, Eq, Serialize)]
pub struct HashHalf(pub [u8; 16]);

impl fmt::Debug for HashHalf {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "HashHalf({})", hex::encode(self.0))
	}
}

impl fmt::Display for HashHalf {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", hex::encode(self.0))
	}
}

impl PartialEq for HashHalf {
	fn eq(&self, other: &Self) -> bool {
		subtle::ConstantTimeEq::ct_eq(&self.0[..], &other.0[..]).into()
	}
}

/// Underlying storage type of unencrypted entry header or body.
pub type PlainMap<V> = HashMap<String, V>;

/// Unencrypted entry header or body.
#[derive(Clone, Decode, Default, Encode)]
pub struct Unencrypted<V>(PlainMap<V>);

impl<V> Unencrypted<V> {
	/// Create empty encrypted body.
	pub fn new() -> Self {
		Self(PlainMap::new())
	}

	/// Insert unencrypted item.
	pub fn insert(&mut self, key: String, value: V) {
		self.0.insert(key, value);
	}

	/// Get unencrypted item.
	pub fn get(&self, key: &str) -> Option<&V> {
		self.0.get(key)
	}
}

impl<V> std::ops::Index<&str> for Unencrypted<V> {
	type Output = V;

	fn index(&self, index: &str) -> &Self::Output {
		&self.0[index]
	}
}

impl<V: Zeroize> Zeroize for Unencrypted<V> {
	fn zeroize(&mut self) {
		// since we enforce V to impl `Zeroize`, they'll be zeroized on drop
		// (i.e. when we clear map)
		self.0.clear();
	}
}

/// Encrypted entry header or body.
pub type Encrypted = SecretWithAutorization;

/// Entry that holds secret.
#[derive(Clone, Debug, Decode, Default, Deserialize, Encode, Serialize)]
pub struct Entry<Header, Body> {
	/// Entry header.
	pub header: Header,
	/// Entry body.
	pub body: Body,
}

impl<Header, Body> Entry<Header, Body> {
	/// Create empty [Entry].
	pub fn new() -> Self
	where
		Header: Default,
		Body: Default,
	{
		Entry {
			header: Default::default(),
			body: Default::default(),
		}
	}

	/// Switch header type of this [Entry].
	pub fn switch_header<NewHeader>(mut self, new_header: NewHeader) -> Entry<NewHeader, Body>
	where
		Header: Zeroize,
	{
		self.header.zeroize();
		self.switch_header_no_zeroize(new_header)
	}

	/// Switch header type of this [Entry]. No zeroization for previous
	/// header is performed, so it is suited for encrypted-to-unencrypted transformations.
	pub fn switch_header_no_zeroize<NewHeader>(
		self,
		new_header: NewHeader,
	) -> Entry<NewHeader, Body> {
		Entry {
			header: new_header,
			body: self.body,
		}
	}

	/// Switch body type of this [Entry].
	pub fn switch_body<NewBody>(mut self, new_body: NewBody) -> Entry<Header, NewBody>
	where
		Body: Zeroize,
	{
		self.body.zeroize();
		self.switch_body_no_zeroize(new_body)
	}

	/// Switch body type of this [Entry]. No zeroization for previous
	/// body is performed, so it is suited for encrypted-to-unencrypted transformations.
	pub fn switch_body_no_zeroize<NewBody>(self, new_body: NewBody) -> Entry<Header, NewBody> {
		Entry {
			header: self.header,
			body: new_body,
		}
	}
}

impl<HeaderV, BodyV> Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>
where
	Self: Encode,
{
	/// Compute hash of the plain, unencrypted entry.
	pub fn hash(&self) -> Result<Hash, Error> {
		bincode::encode_to_vec(self, bincode_config())
			.map(|data| Hash::hash_raw(&data))
			.map_err(|e| ErrorKind::EncodeError(e).into())
	}
}
