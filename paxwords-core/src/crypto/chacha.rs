//! Helper functions to perform symmetric encryption and decryption using ChaCha20-Poly1305 cipher.

use crate::{
	Error, ErrorKind,
	types::{Authorization, Secret},
};

use chacha20poly1305::{
	ChaCha20Poly1305, Key,
	aead::{Aead, AeadCore, KeyInit, rand_core::OsRng as ChaChaOsRng},
};
use hkdf::Hkdf;
use rand_core::{OsRng, TryRngCore, UnwrapErr};
use secrecy::{ExposeSecret, SecretSlice, zeroize::ZeroizeOnDrop};
use sha2::Sha256;
use std::ops::{Deref, DerefMut};
use thiserror_context::Context;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

/// An encryption key. It is here to avoid non-zeroizing [u8; 32] when it is derived and/or decrypted.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey(pub(super) [u8; 32]);

impl Deref for EncryptionKey {
	type Target = [u8; 32];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DerefMut for EncryptionKey {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

impl From<[u8; 32]> for EncryptionKey {
	fn from(value: [u8; 32]) -> Self {
		Self(value)
	}
}

impl From<EncryptionKey> for Key {
	fn from(value: EncryptionKey) -> Self {
		Key::from(value.0)
	}
}

impl From<Key> for EncryptionKey {
	fn from(value: Key) -> Self {
		EncryptionKey(value.into())
	}
}

/// Encrypt [secret] with random key.
pub(super) fn encrypt_secret<T: ExposeSecret<U>, U: AsRef<[u8]> + ?Sized>(
	secret: T,
) -> Result<(Secret, EncryptionKey), Error> {
	// it is written as a single large function, without any code reusing to keep
	// secret(s) moving/copying under control

	// 1: generate random enc_key
	// INPUTS: -
	// CONSUMED INPUTS: -
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: enc_key
	let enc_key = ChaCha20Poly1305::generate_key(&mut ChaChaOsRng);

	// 2: generate random enc_nonce
	// INPUTS: -
	// CONSUMED INPUTS: -
	// SAFE OUTPUTS: enc_nonce
	// UNSAFE OUTPUTS: -
	let enc_nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);

	// 3: encrypt secret with enc_key and enc_nonce
	// INPUTS: secret, enc_key, enc_nonce
	// CONSUMED INPUTS: secret
	// SAFE OUTPUTS: secret_enc
	// UNSAFE OUTPUTS: -
	let secret_enc = ChaCha20Poly1305::new(&enc_key)
		.encrypt(&enc_nonce, secret.expose_secret().as_ref())
		.map_err(ErrorKind::EncryptionFailed)
		.context("error encrypting secret")?;
	drop(secret);

	// UNSAFE LIFETIME:
	// - secret: [...; 3]
	// - enc_key: [1; ...]

	let secret = Secret {
		enc_nonce: enc_nonce.into(),
		secret_enc,
	};

	Ok((secret, enc_key.into()))
}

/// Generate [Authorization] for given entity_pub.
pub(super) fn generate_authorization(
	entity_pub: &PublicKey,
	enc_key: EncryptionKey,
) -> Result<Authorization, Error> {
	// 1: generate ephemeral key pair to generate authorization
	// INPUTS: -
	// CONSUMED INPUTS: -
	// SAFE OUTPUTS: eph_public
	// UNSAFE OUTPUTS: eph_private
	let eph_priv = EphemeralSecret::random_from_rng(&mut UnwrapErr(OsRng));
	let eph_pub = PublicKey::from(&eph_priv);

	// 2: generate shared key for authorization
	// INPUTS: entity_pub
	// CONSUMED OUPTUTS: eph_priv
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: shared_key
	let shared_key = eph_priv.diffie_hellman(entity_pub);
	// diffie_hellman consumes eph_priv

	// 3: generate salt for new secret key
	// INPUTS: -
	// CONSUMED OUPTUTS: -
	// SAFE OUTPUTS: enc_key_salt
	// UNSAFE OUTPUTS: -
	let mut enc_key_salt = [0u8; 16];
	OsRng
		.try_fill_bytes(&mut enc_key_salt)
		.map_err(ErrorKind::RandomGenerationFailed)
		.context("error generating enc_key_salt")?;

	// 4: derive new key from shared key
	// INPUTS: enc_key_salt
	// CONSUMED OUPTUTS: shared_key
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: enc_key_key
	let mut enc_key_key = EncryptionKey::default();
	Hkdf::<Sha256>::new(Some(&enc_key_salt[..]), shared_key.as_bytes())
		.expand(&[], &mut enc_key_key.0)
		.map_err(ErrorKind::KeyDerivationFailed)
		.context("error deriving enc_key_key from shared_key")?;
	let mut enc_key_key: Key = enc_key_key.into();
	drop(shared_key);

	// 5: generate random enc_key_nonce
	// INPUTS: -
	// CONSUMED INPUTS: -
	// SAFE OUTPUTS: enc_key_nonce
	// UNSAFE OUTPUTS: -
	let enc_key_nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);

	// 6: encrypt enc_key with enc_key_key and enc_key_nonce
	// INPUTS: enc_key, enc_key_key, enc_key_nonce
	// CONSUMED INPUTS: enc_key
	// SAFE OUTPUTS: enc_key_enc
	// UNSAFE OUTPUTS: -
	let enc_key_enc = ChaCha20Poly1305::new(&enc_key_key)
		.encrypt(&enc_key_nonce, enc_key.as_slice())
		.map_err(ErrorKind::EncryptionFailed)
		.context("error encrypting enc_key")?;
	// Key implements Copy, so call zeroize instead of drop
	drop(enc_key);
	enc_key_key.zeroize();

	// UNSAFE LIFETIME:
	// - enc_key: [...; 6]
	// - eph_priv: [1; 2]
	// - shared_key: [2; 4]
	// - enc_key_key: [4; 6]

	const PROOF: &str = "the length of the secret, encrypted with chacha is the length of plaintext + 16;\
		plaintext is 32 bytes - the length of shared key on Curve25519;\
		qed";

	Ok(Authorization {
		eph_pub: eph_pub.to_bytes(),
		enc_key_salt,
		enc_key_nonce: enc_key_nonce.into(),
		enc_key_enc: enc_key_enc.get(..48).expect(PROOF).try_into().expect(PROOF),
	})
}

/// Authorize entity with entity_priv private key to use authorization.
pub(super) fn authorize(
	entity_priv: StaticSecret,
	authorization: &Authorization,
) -> Result<EncryptionKey, Error> {
	// it is written as a single large function, without any code reusing to keep
	// secret(s) moving/copying under control

	// 1: reconstruct shared_key using entity_priv and eph_pub
	// INPUTS: eph_pub
	// CONSUMED INPUTS: entity_priv
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: shared_key
	let shared_key = entity_priv.diffie_hellman(&PublicKey::from(authorization.eph_pub));
	drop(entity_priv);

	// 2: derive enc_key_key from shared_key
	// INPUTS: enc_key_salt
	// CONSUMED INPUTS: shared_key
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: enc_key_key
	let mut enc_key_key = EncryptionKey::default();
	Hkdf::<Sha256>::new(Some(&authorization.enc_key_salt), shared_key.as_bytes())
		.expand(&[], &mut enc_key_key.0)
		.map_err(ErrorKind::KeyDerivationFailed)
		.context("error deriving enc_key_key from shared_key")?;
	drop(shared_key);

	// 3: decrypt enc_key using enc_key_key
	// INPUTS: enc_key_nonce, enc_key_enc
	// CONSUMED INPUTS: enc_key_key
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: enc_key
	const PROOF: &str = "the length of the secret, encrypted with chacha is the length of plaintext + 16;\
		the length of enc_key_enc is 48;\
		qed";

	let enc_key = ChaCha20Poly1305::new(&enc_key_key.0.into())
		.decrypt(
			&authorization.enc_key_nonce.into(),
			&authorization.enc_key_enc[..],
		)
		.map_err(ErrorKind::DecryptionFailed)
		.context("error decrypting enc_key")?;
	let enc_key = EncryptionKey(enc_key.get(..32).expect(PROOF).try_into().expect(PROOF));
	drop(enc_key_key);

	// UNSAFE LIFETIME:
	// - entity_priv: [...; 1]
	// - shared_key: [1; 2]
	// - enc_key_key: [2; 3]
	// - enc_key: [3; ...]

	Ok(enc_key)
}

/// Decrypt [secret] using [authorization] for the entity with [entity_priv].
pub(super) fn decrypt_secret(
	enc_key: EncryptionKey,
	secret: &Secret,
) -> Result<SecretSlice<u8>, Error> {
	// it is written as a single large function, without any code reusing to keep
	// secret(s) moving/copying under control

	// 1: decrypt secret using enc_key
	// INPUTS: enc_nonce, secret_enc
	// CONSUMED INPUTS: enc_key
	// SAFE OUTPUTS: -
	// UNSAFE OUTPUTS: secret
	let mut enc_key = enc_key.into();
	let secret = ChaCha20Poly1305::new(&enc_key)
		.decrypt(&secret.enc_nonce.into(), &secret.secret_enc[..])
		.map_err(ErrorKind::DecryptionFailed)
		.context("error decrypting secret")?;
	let secret: SecretSlice<u8> = secret.into();
	enc_key.zeroize();

	// UNSAFE LIFETIME:
	// - entity_priv: [0; 1]
	// - shared_key: [1; 2]
	// - enc_key_key: [2; 3]
	// - enc_key: [3; 4]

	Ok(secret)
}

#[cfg(test)]
mod tests {
	use super::*;

	use secrecy::SecretString;

	#[test]
	fn encryption_key_is_zeroized_on_drop() {
		let mut key = EncryptionKey([42; 32]);
		let key_ptr = key.0.as_ptr();
		unsafe {
			(0..32).for_each(|i| assert_eq!(*key_ptr.add(i), 42, "{i}"));
			// reading mem after drop is undefined, but since object is on the stack and
			// there are no other operations between drop and read, let's assume it is ok
			std::ptr::drop_in_place(&mut key);
			(0..32).for_each(|i| assert_eq!(*key_ptr.add(i), 0, "{i}"));
		}
	}

	#[test]
	fn encryption_results_are_different_for_the_same_secret() {
		let secret: SecretString = "secret_value".into();
		let (secret_enc1, _) = encrypt_secret(secret.clone()).unwrap();
		let (secret_enc2, _) = encrypt_secret(secret.clone()).unwrap();
		assert_ne!(secret_enc1.secret_enc, secret_enc2.secret_enc);
	}

	#[test]
	fn full_encryption_cycle() {
		let secret: SecretString = "secret_value".into();
		let entity_priv = StaticSecret::from([1; 32]);
		let entity_pub = PublicKey::from(&entity_priv);

		let (secret_enc, enc_key) = encrypt_secret(secret.clone()).unwrap();
		let secret_auth = generate_authorization(&entity_pub, enc_key).unwrap();

		let enc_key = authorize(entity_priv, &secret_auth).unwrap();
		let secret_dec = decrypt_secret(enc_key, &secret_enc).unwrap();

		assert_eq!(
			secret.expose_secret().as_bytes(),
			secret_dec.expose_secret()
		);
	}
}
