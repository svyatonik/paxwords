#[cfg(not(any(feature = "enable-keyring", feature = "enable-memsecurity")))]
compile_error!("One of features must be enabled: enable-keyring or enable-memsecurity");

pub(super) use keystorage::*;

#[cfg(feature = "enable-keyring")]
mod keystorage {
	use super::super::chacha::EncryptionKey;
	use crate::{Error, ErrorKind};

	use keyring::Entry;
	use rand_core::TryRngCore;
	use std::process;
	use thiserror_context::Context;

	// using keyring is not the best idea - it creates persistent entries on Windows and MacOs

	/// Service name for paxwords entries.
	const PAXWORDS_SERVICE: &str = "PAXWORDS";
	/// User name for paxwords entries.
	const PAXWORDS_USER: &str = "MASTER_PASSWORD";

	/// Keyring identifier.
	#[derive(Clone, Copy)]
	pub struct KeyringId(u64);

	/// Save key used to encrypt master password in the OS keyring.
	pub fn save_entity_priv_key(entity_priv_key: EncryptionKey) -> Result<KeyringId, Error> {
		rand_core::OsRng
			.try_next_u64()
			.map(KeyringId)
			.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))
			.and_then(|id| keyring_entry(id).map(|entry| (id, entry)))
			.and_then(|(id, entry)| {
				entry
					.set_secret(&entity_priv_key[..])
					.map(|_| id)
					.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))
			})
			.context("error saving entity_priv_key to keyring")
	}

	/// Return key used to encrypt master password from the OS keyring.
	pub fn load_entity_priv_key(id: KeyringId) -> Result<EncryptionKey, Error> {
		keyring_entry(id)
			.and_then(|entry| {
				entry
					.get_secret()
					.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))
			})
			.and_then(|secret| {
				if secret.len() != 32 {
					return Err(Error::from(ErrorKind::MasterKeyRecoveryFailed));
				}

				let mut entity_priv_key = EncryptionKey::default();
				// we've checked that secret len is 32, so it is safe
				entity_priv_key.copy_from_slice(&secret[..32]);
				Ok(entity_priv_key)
			})
			.context("error reading entity_priv_key from keyring")
	}

	/// Remove keyring entry.
	pub fn remove_entity_priv_key(id: KeyringId) -> Result<(), Error> {
		keyring_entry(id).and_then(|entry| {
			entry
				.delete_credential()
				.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))
		})
	}

	/// Get corresponding keyring entry.
	fn keyring_entry(id: KeyringId) -> Result<Entry, Error> {
		Entry::new(
			PAXWORDS_SERVICE,
			&format!("{}:{}:{}", PAXWORDS_USER, process::id(), id.0),
		)
		.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))
		.context("error opening keyring entry")
	}

	#[cfg(test)]
	mod test {
		use super::*;

		#[test]
		fn full_keyring_cycle() {
			let id1 = save_entity_priv_key(EncryptionKey::from([42; 32])).unwrap();
			assert_eq!([42; 32], *load_entity_priv_key(id1).unwrap());

			let id2 = save_entity_priv_key(EncryptionKey::from([43; 32])).unwrap();
			assert_eq!([43; 32], *load_entity_priv_key(id2).unwrap());

			assert_ne!(id1.0, id2.0);

			remove_entity_priv_key(id1).unwrap();
			assert!(load_entity_priv_key(id1).is_err());
		}
	}
}

#[cfg(feature = "enable-memsecurity")]
mod keystorage {
	use super::super::chacha::EncryptionKey;
	use crate::{Error, ErrorKind};

	use memsecurity::EncryptedMem;
	use parking_lot::Mutex;
	use rand_core::TryRngCore;
	use std::{collections::HashMap, sync::OnceLock};

	/// All encryption keys are stored in encrypted form using `memsecurity` crate.
	static ENCRYPTION_KEYS: OnceLock<Mutex<HashMap<KeyringId, EncryptedMem>>> = OnceLock::new();

	/// Keyring identifier.
	#[derive(Clone, Copy, Eq, Hash, PartialEq)]
	pub struct KeyringId(u64);

	/// Save key used to encrypt master password in the OS keyring.
	pub fn save_entity_priv_key(entity_priv_key: EncryptionKey) -> Result<KeyringId, Error> {
		rand_core::OsRng
			.try_next_u64()
			.map(KeyringId)
			.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))
			.and_then(|id| {
				let mut encrypted_key = EncryptedMem::new();
				encrypted_key
					.encrypt(&entity_priv_key.0)
					.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))?;
				encryption_keys().lock().insert(id, encrypted_key);
				Ok(id)
			})
	}

	/// Return key used to encrypt master password from the OS keyring.
	pub fn load_entity_priv_key(id: KeyringId) -> Result<EncryptionKey, Error> {
		encryption_keys()
			.lock()
			.get(&id)
			.and_then(|mem| mem.decrypt_32byte().ok())
			.map(|k| EncryptionKey(*k.expose_borrowed()))
			.ok_or_else(|| Error::from(ErrorKind::MasterKeyRecoveryFailed))
	}

	/// Remove keyring entry.
	pub fn remove_entity_priv_key(id: KeyringId) -> Result<(), Error> {
		encryption_keys().lock().remove(&id);
		Ok(())
	}

	fn encryption_keys() -> &'static Mutex<HashMap<KeyringId, EncryptedMem>> {
		ENCRYPTION_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
	}
}
