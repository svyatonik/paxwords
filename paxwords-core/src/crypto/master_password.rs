//! Master password is the only thing that user should know to access paxwords store.
//! A Curve25519 private key is derived from that password using Password-Based Key Derivation
//! Function v2 (PBKDF2).

use super::{chacha, keyring};
use crate::{
	EncryptionKey, Error, ErrorKind,
	types::{Secret, SecretWithAutorization},
};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};
use sha2::Sha256;
use thiserror_context::Context;
use x25519_dalek::{PublicKey, StaticSecret};

/// Holds the Curve25519 key (optionally derived from password, typed by user). It is stored
/// in mlocked memory in encrypted form. The key used to encrypt is stored in the operating system keyring.
/// Time, when the key is stored in unencrypted form in RAM is minimized.
pub struct MasterPassword {
	/// Unencrypted entity public key.
	entity_pub: PublicKey,
	/// An encrypted private entity private key. It is protected with mlock, mprotect and zeroized on drop.
	/// The key that is used to encrypt the master key is stored in the operating system keyring.
	entity_priv_enc: Secret,
	/// Keyring identificator. It is required if multiple instances of the same `MasterPassword` are
	/// active in the same environment.
	keyring_id: keyring::KeyringId,
}

impl Drop for MasterPassword {
	fn drop(&mut self) {
		if let Err(e) = keyring::remove_entity_priv_key(self.keyring_id) {
			// this is bad, but not critical on linux, since keyring storage (keyutils)
			// is not persitent there and all our dangling entries will be removed
			// on logout. On other OS, this error is really bad. Maybe there's a better
			// way to handle that?
			tracing::error!("failed to remove master password entrty from keyring: {e:?}")
		}
	}
}

impl MasterPassword {
	/// Create master password from user defined password.
	pub fn from_password_secret(password: SecretString) -> Result<Self, Error> {
		const SALT: &[u8; 16] = b"p_a_x_w_o_r_d_s_";
		const PBKDF_ROUNDS: u32 = 100_000;

		// derive private key using pbkdf2
		let mut entity_priv = SecretBox::new(Box::new([0u8; 32]));
		pbkdf2::pbkdf2_hmac::<Sha256>(
			password.expose_secret().as_bytes(),
			SALT,
			PBKDF_ROUNDS,
			entity_priv.expose_secret_mut(),
		);
		Self::from_entity_key(entity_priv)
	}

	/// Create master password from previously derived entity key.
	pub fn from_entity_key(entity_priv: SecretBox<[u8; 32]>) -> Result<Self, Error> {
		// compute public key
		let static_secret = StaticSecret::from(*entity_priv.expose_secret());
		let entity_pub = PublicKey::from(&static_secret);
		drop(static_secret);

		// encrypt private key
		let (entity_priv_enc, entity_priv_key) = chacha::encrypt_secret(entity_priv)?;

		// write entity_priv_key, used to encrypt private key into key storage
		let keyring_id = keyring::save_entity_priv_key(entity_priv_key)?;

		Ok(Self {
			entity_pub,
			entity_priv_enc,
			keyring_id,
		})
	}

	/// Rrturn entity public key.
	pub fn public(&self) -> &PublicKey {
		&self.entity_pub
	}

	/// Derive key from the master key.
	pub fn derive_key(&self, salt: &[u8]) -> Result<EncryptionKey, Error> {
		let entity_priv = self.load_entity_priv()?;
		let mut derived_key = EncryptionKey::default();
		hkdf::Hkdf::<Sha256>::new(Some(salt), entity_priv.as_bytes())
			.expand(&[], &mut derived_key.0)
			.map_err(ErrorKind::KeyDerivationFailed)
			.context("error deriving enc_key_key from shared_key")?;
		Ok(derived_key)
	}

	/// Encrypt given secret.
	pub fn encrypt(&self, secret: SecretSlice<u8>) -> Result<SecretWithAutorization, Error> {
		let (secret_enc, enc_key) = chacha::encrypt_secret(secret)?;
		let authorization = chacha::generate_authorization(&self.entity_pub, enc_key)?;
		Ok(SecretWithAutorization {
			secret: secret_enc,
			authorization,
		})
	}

	/// Decrypt previously encrypted secret.
	pub fn decrypt(&self, secret: &SecretWithAutorization) -> Result<SecretSlice<u8>, Error> {
		// authorize
		let enc_key = chacha::authorize(self.load_entity_priv()?, &secret.authorization)?;
		// ... and decrypt
		chacha::decrypt_secret(enc_key, &secret.secret)
	}

	fn load_entity_priv(&self) -> Result<StaticSecret, Error> {
		// read encryption key from keyring
		let entity_priv_key = keyring::load_entity_priv_key(self.keyring_id)?;
		// and decrypt private key using encryption key
		let entity_priv_slice = chacha::decrypt_secret(entity_priv_key, &self.entity_priv_enc)?;
		// decrypt entity private key
		let entity_priv_slice_sized: &[u8; 32] = entity_priv_slice
			.expose_secret()
			.get(..32)
			.ok_or_else(|| Error::from(ErrorKind::MasterKeyRecoveryFailed))?
			.try_into()
			.map_err(|_| Error::from(ErrorKind::MasterKeyRecoveryFailed))?;
		let entity_priv = StaticSecret::from(*entity_priv_slice_sized);
		drop(entity_priv_slice);
		Ok(entity_priv)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn master_keys_from_same_password_are_equal() {
		let master1 = MasterPassword::from_password_secret("password".into()).unwrap();
		let master2 = MasterPassword::from_password_secret("password".into()).unwrap();
		assert_eq!(master1.entity_pub, master2.entity_pub);
		assert_ne!(
			master1.entity_priv_enc.secret_enc,
			master2.entity_priv_enc.secret_enc
		);
	}

	#[test]
	fn master_keys_from_different_passwords_are_different() {
		let master1 = MasterPassword::from_password_secret("password1".into()).unwrap();
		let master2 = MasterPassword::from_password_secret("password2".into()).unwrap();
		assert_ne!(master1.entity_pub, master2.entity_pub);
		assert_ne!(
			master1.entity_priv_enc.secret_enc,
			master2.entity_priv_enc.secret_enc
		);
	}

	#[test]
	fn master_keys_from_same_ext_key_are_equal() {
		let master1 =
			MasterPassword::from_entity_key(SecretBox::new(Box::new([42u8; 32]))).unwrap();
		let master2 =
			MasterPassword::from_entity_key(SecretBox::new(Box::new([42u8; 32]))).unwrap();
		assert_eq!(master1.entity_pub, master2.entity_pub);
		assert_ne!(
			master1.entity_priv_enc.secret_enc,
			master2.entity_priv_enc.secret_enc
		);
	}

	#[test]
	fn master_keys_from_different_ext_keys_are_different() {
		let master1 =
			MasterPassword::from_entity_key(SecretBox::new(Box::new([42u8; 32]))).unwrap();
		let master2 =
			MasterPassword::from_entity_key(SecretBox::new(Box::new([43u8; 32]))).unwrap();
		assert_ne!(master1.entity_pub, master2.entity_pub);
		assert_ne!(
			master1.entity_priv_enc.secret_enc,
			master2.entity_priv_enc.secret_enc
		);
	}

	#[test]
	fn full_master_password_cycle() {
		let secret = "secret";
		let master = MasterPassword::from_password_secret("password".into()).unwrap();
		let secret_enc = master
			.encrypt(SecretBox::new(
				secret.as_bytes().to_vec().into_boxed_slice(),
			))
			.unwrap();
		let secret_dec = master.decrypt(&secret_enc).unwrap();
		assert_eq!(secret.as_bytes(), secret_dec.expose_secret());
	}

	#[test]
	fn encryption_results_are_different_for_the_same_secret() {
		let secret = "secret";
		let master = MasterPassword::from_password_secret("password".into()).unwrap();
		let secret_enc1 = master
			.encrypt(SecretBox::new(
				secret.as_bytes().to_vec().into_boxed_slice(),
			))
			.unwrap();
		let secret_enc2 = master
			.encrypt(SecretBox::new(
				secret.as_bytes().to_vec().into_boxed_slice(),
			))
			.unwrap();
		assert_ne!(secret_enc1.secret.secret_enc, secret_enc2.secret.secret_enc);
	}

	#[test]
	fn decryption_fails_when_authorization_is_wrong() {
		let secret = "secret";
		let master = MasterPassword::from_password_secret("password".into()).unwrap();
		let mut secret_enc = master
			.encrypt(SecretBox::new(
				secret.as_bytes().to_vec().into_boxed_slice(),
			))
			.unwrap();
		secret_enc.authorization.eph_pub = [42u8; 32];
		assert!(master.decrypt(&secret_enc).is_err());
	}
}
