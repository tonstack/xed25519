use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand_core::OsRng;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use x25519_dalek::{PublicKey, StaticSecret};

fn unsized_to_fixed(array: &[u8]) -> [u8; 32] {
  let mut bytes = [0u8; 32];

  bytes.copy_from_slice(&array[..32]);

  bytes
}

fn x25519_to_ed25519(key: PublicKey, sign_bit: u8) -> PublicKey {
  PublicKey::from(
      MontgomeryPoint(key.to_bytes())
          .to_edwards(sign_bit)
          .unwrap()
          .compress()
          .to_bytes()
  )
}

fn ed25519_to_x25519(key: PublicKey) -> PublicKey {
  PublicKey::from(
      CompressedEdwardsY::from_slice(&key.to_bytes())
          .decompress()
          .unwrap()
          .to_montgomery()
          .to_bytes()
  )
}

#[napi(object, js_name = "ECDHKeys")]
pub struct ECDHKeys {
  pub public: Uint8Array,
  pub shared: Uint8Array
}

#[napi(js_name = "xed25519_ecdh")]
pub fn xed25519_ecdh(peer_public_key: Uint8Array, client_private_key: Option<Uint8Array>) -> ECDHKeys {
  let peer_public: PublicKey = {
      let bytes = unsized_to_fixed(peer_public_key.as_ref());

      PublicKey::from(bytes)
  };

  let secret = if client_private_key.is_none() {
      StaticSecret::new(OsRng)
  } else {
      let bytes = unsized_to_fixed(client_private_key.unwrap().as_ref());

      StaticSecret::from(bytes)
  };

  let x25519_client_public_key = PublicKey::from(&secret);
  let x25519_peer_public_key = ed25519_to_x25519(peer_public);

  let public = x25519_to_ed25519(x25519_client_public_key, 0);
  let shared = secret.diffie_hellman(&x25519_peer_public_key);

  ECDHKeys {
      public: Uint8Array::new(public.to_bytes().to_vec()),
      shared: Uint8Array::new(shared.to_bytes().to_vec())
  }
}
