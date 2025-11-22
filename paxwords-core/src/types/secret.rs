use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

/// A secret, encrypted with ChaCha20-Poly1305. It is safe to store the value of this structure in plaintext.
#[derive(Clone, Debug, Decode, Deserialize, Encode, Serialize, Zeroize)]
pub struct Secret {
	/// Nonce used to encrypt the original secret.
	pub enc_nonce: [u8; 12],
	/// Original secret, encrypted with ChaCha20-Poly1305.
	pub secret_enc: Vec<u8>,
}

/// Authorization for the entity to use the [Secret]. It is safe to store the
/// value of this structure in plaintext.
#[derive(Clone, Debug, Decode, Deserialize, Encode, Serialize, Zeroize)]
pub struct Authorization {
	/// A public portion of ephemeral key used to generate this authorization.
	pub eph_pub: [u8; 32],
	/// 16-bytes salt looks like optimal value.
	pub enc_key_salt: [u8; 16],
	/// Nonce used to encrypt the original secret. It is always 12 bytes in ChaCha20-Poly1305.
	pub enc_key_nonce: [u8; 12],
	/// It is the key, used to encrypt [Secret::secret_enc], encrypted with shared key (x25519
	/// Diffie-Hellman with the entity and [Authorization::eph_pub]).
	#[serde(with = "BigArray")]
	pub enc_key_enc: [u8; 48],
}

/// Encrypted secret with authorization to use it.
#[derive(Clone, Debug, Decode, Deserialize, Encode, Serialize, Zeroize)]
pub struct SecretWithAutorization {
	/// A secret part that is shared by all authorizations.
	pub secret: Secret,
	/// An authorization for the secret, generated for specific entity.
	pub authorization: Authorization,
}
