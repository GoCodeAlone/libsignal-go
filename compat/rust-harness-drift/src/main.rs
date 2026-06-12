//
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Drift generator for the version-stable libsignal primitives.
//!
//! This is a deliberately minimal sibling of `compat/rust-harness`. Where that
//! harness is pinned to upstream `v0.91.0` and is the behavioral contract, this
//! crate floats on upstream `main` (see Cargo.toml) so the weekly compat-drift
//! workflow can detect when upstream changes the bytes of a primitive we
//! consider version-stable.
//!
//! It exposes ONE mode, `gen-vectors <domain>`, for the stable domains only:
//!
//!   * `curve` — XEdDSA sign/verify (deterministic 64-byte nonce) + X25519 ECDH
//!   * `kem-decaps` — Kyber1024 encapsulate/decapsulate quadruples
//!   * `hkdf` — the Double Ratchet key derivations (chain/message/root/pqxdh)
//!
//! Output is byte-identical to `compat/rust-harness gen-vectors <domain>` when
//! both link the same upstream revision: same `VECTOR_SEED`, same seeded
//! ChaCha20 draw order, same JSON schema (so `compat/vectors_test.go` consumes
//! either interchangeably). The drift signal is exactly a byte difference
//! between this crate's `main` output and the committed v0.91.0 vectors.
//!
//! Hard constraint: NO `messages` / `fingerprint` / `interop` surface here.
//! Those exercise the session/group/message API that legitimately evolves on
//! `main`; tracking them here would produce noise, not signal. They live only
//! in `compat/rust-harness` and are extended there (T19/T21/T24/T28).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use sha2::Sha256;
use std::io::{self, Write};

use libsignal_protocol::{kem, KeyPair};

/// Fixed seed for the deterministic CSPRNG, identical to the pinned harness so
/// the two emit byte-identical vectors when linking the same upstream revision.
const VECTOR_SEED: u64 = 0x5163_6e61_6c47_6f00; // "SignalGo\0"-ish, stable.

fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(VECTOR_SEED)
}

/// Replays a fixed byte buffer as an RNG, then panics if drained. Used to feed
/// the recorded 64-byte XEdDSA signing nonce so signatures are reproducible.
struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl rand_core::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.pos + dest.len();
        assert!(
            end <= self.bytes.len(),
            "FixedRng exhausted: needed {end} bytes, have {}",
            self.bytes.len()
        );
        dest.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
    }
}

impl rand_core::CryptoRng for FixedRng {}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// Case counts match the pinned harness so consumption-gate thresholds hold for
// either source (hkdf >= 20 per sub-domain, kem-decaps >= 100).
const N_CURVE_SIGN: u32 = 24;
const N_CURVE_ECDH: u32 = 24;
const N_KEM: u32 = 128;
const N_HKDF_PER_SUBDOMAIN: u32 = 24;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("gen-vectors") => match args.get(2).map(String::as_str) {
            Some(domain) => gen_vectors(domain),
            None => Err("gen-vectors requires a <domain> argument".to_string()),
        },
        Some(other) => Err(format!("unknown mode {other:?}; expected gen-vectors")),
        None => Err("usage: rust-harness-drift gen-vectors <domain>".to_string()),
    };
    if let Err(msg) = result {
        eprintln!("rust-harness-drift: {msg}");
        std::process::exit(2);
    }
}

fn gen_vectors(domain: &str) -> Result<(), String> {
    let mut batch = json!({
        "domain": domain,
        "seed": format!("{VECTOR_SEED:#018x}"),
    });
    let obj = batch.as_object_mut().expect("object");
    match domain {
        "curve" => {
            obj.insert("cases".into(), Value::Array(gen_curve()));
        }
        "kem-decaps" => {
            obj.insert("cases".into(), Value::Array(gen_kem_decaps()));
        }
        "hkdf" => {
            obj.insert("subdomains".into(), gen_hkdf());
        }
        other => {
            return Err(format!(
                "unknown or non-stable domain {other:?}; this crate generates only curve|kem-decaps|hkdf \
                 (messages/fingerprint live in compat/rust-harness)"
            ));
        }
    };
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &batch).map_err(|e| e.to_string())?;
    writeln!(out).map_err(|e| e.to_string())?;
    Ok(())
}

/// curve domain: XEdDSA sign/verify with a recorded deterministic nonce, plus
/// X25519 ECDH agreement. Matches compat/rust-harness gen_curve byte-for-byte.
fn gen_curve() -> Vec<Value> {
    use rand_core::RngCore;
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for i in 0..N_CURVE_SIGN {
        let signer = KeyPair::generate(&mut rng);
        let message: Vec<u8> = (0..(8 + i as usize))
            .map(|j| (i as u8).wrapping_add(j as u8))
            .collect();
        let mut nonce = [0u8; 64];
        rng.fill_bytes(&mut nonce);
        let signature = signer
            .private_key
            .calculate_signature(&message, &mut FixedRng::new(nonce.to_vec()))
            .expect("sign");
        let verified = signer.public_key.verify_signature(&message, &signature);
        cases.push(json!({
            "op": "xeddsa",
            "private_key": hex(&signer.private_key.serialize()),
            "public_key": hex(&signer.public_key.serialize()),
            "message": hex(&message),
            "nonce": hex(&nonce),
            "signature": hex(&signature),
            "verified": verified,
        }));
    }

    for _ in 0..N_CURVE_ECDH {
        let a = KeyPair::generate(&mut rng);
        let b = KeyPair::generate(&mut rng);
        let ab = a
            .private_key
            .calculate_agreement(&b.public_key)
            .expect("agree ab");
        let ba = b
            .private_key
            .calculate_agreement(&a.public_key)
            .expect("agree ba");
        cases.push(json!({
            "op": "ecdh",
            "a_private": hex(&a.private_key.serialize()),
            "a_public": hex(&a.public_key.serialize()),
            "b_private": hex(&b.private_key.serialize()),
            "b_public": hex(&b.public_key.serialize()),
            "shared": hex(&ab),
            "shared_matches": ab == ba,
        }));
    }

    cases
}

/// kem-decaps domain: Kyber1024 (pk, sk, ct, ss) quadruples with an
/// encapsulate/decapsulate round-trip. Matches compat/rust-harness.
fn gen_kem_decaps() -> Vec<Value> {
    let mut rng = seeded_rng();
    let mut cases = Vec::new();
    for _ in 0..N_KEM {
        let kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let (ss_enc, ct) = kp.public_key.encapsulate(&mut rng).expect("encapsulate");
        let ss_dec = kp.secret_key.decapsulate(&ct).expect("decapsulate");
        cases.push(json!({
            "key_type": "kyber1024",
            "public_key": hex(&kp.public_key.serialize()),
            "secret_key": hex(&kp.secret_key.serialize()),
            "ciphertext": hex(&ct),
            "shared_secret": hex(&ss_enc),
            "decapsulated_matches": ss_enc.as_ref() == ss_dec.as_ref(),
        }));
    }
    cases
}

/// `ChainKey::calculate_base_material`: HMAC-SHA256(chain_key, seed).
fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

/// hkdf domain: the four Double Ratchet derivations, formulas verbatim from
/// rust/protocol/src/ratchet/keys.rs and ratchet.rs. Matches compat/rust-harness.
fn gen_hkdf() -> Value {
    use rand_core::RngCore;
    let mut rng = seeded_rng();

    let mut chain_key_cases = Vec::new();
    let mut message_keys_cases = Vec::new();
    let mut root_key_cases = Vec::new();
    let mut pqxdh_secret_cases = Vec::new();

    for _ in 0..N_HKDF_PER_SUBDOMAIN {
        // chain-key
        let mut chain_key = [0u8; 32];
        rng.fill_bytes(&mut chain_key);
        let next_chain_key = hmac_sha256(&chain_key, &[0x02u8]);
        chain_key_cases.push(json!({
            "chain_key": hex(&chain_key),
            "next_chain_key": hex(&next_chain_key),
        }));

        // message-keys
        let mut mk_chain_key = [0u8; 32];
        rng.fill_bytes(&mut mk_chain_key);
        let message_key_seed = hmac_sha256(&mk_chain_key, &[0x01u8]);
        let mut mk_okm = [0u8; 80];
        Hkdf::<Sha256>::new(None, &message_key_seed)
            .expand(b"WhisperMessageKeys", &mut mk_okm)
            .expect("valid output length");
        message_keys_cases.push(json!({
            "chain_key": hex(&mk_chain_key),
            "cipher_key": hex(&mk_okm[0..32]),
            "mac_key": hex(&mk_okm[32..64]),
            "iv": hex(&mk_okm[64..80]),
        }));

        // root-key (with DH)
        let mut root_key = [0u8; 32];
        rng.fill_bytes(&mut root_key);
        let our = KeyPair::generate(&mut rng);
        let their = KeyPair::generate(&mut rng);
        let shared = our
            .private_key
            .calculate_agreement(&their.public_key)
            .expect("agree");
        let mut rk_okm = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&root_key), &shared)
            .expand(b"WhisperRatchet", &mut rk_okm)
            .expect("valid output length");
        root_key_cases.push(json!({
            "root_key": hex(&root_key),
            "our_private": hex(&our.private_key.serialize()),
            "their_public": hex(&their.public_key.serialize()),
            "dh_output": hex(&shared),
            "next_root_key": hex(&rk_okm[0..32]),
            "chain_key": hex(&rk_okm[32..64]),
        }));

        // pqxdh-secret
        let identity = KeyPair::generate(&mut rng);
        let base = KeyPair::generate(&mut rng);
        let their_identity = KeyPair::generate(&mut rng);
        let their_signed_pre = KeyPair::generate(&mut rng);
        let their_one_time = KeyPair::generate(&mut rng);
        let their_kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        let dh1 = identity
            .private_key
            .calculate_agreement(&their_signed_pre.public_key)
            .expect("dh1");
        let dh2 = base
            .private_key
            .calculate_agreement(&their_identity.public_key)
            .expect("dh2");
        let dh3 = base
            .private_key
            .calculate_agreement(&their_signed_pre.public_key)
            .expect("dh3");
        let dh4 = base
            .private_key
            .calculate_agreement(&their_one_time.public_key)
            .expect("dh4");
        let (kyber_ss, kyber_ct) = their_kyber.public_key.encapsulate(&mut rng).expect("kyber");

        let mut secret = Vec::with_capacity(32 * 6);
        secret.extend_from_slice(&[0xFFu8; 32]); // discontinuity bytes
        secret.extend_from_slice(&dh1);
        secret.extend_from_slice(&dh2);
        secret.extend_from_slice(&dh3);
        secret.extend_from_slice(&dh4);
        secret.extend_from_slice(kyber_ss.as_ref());

        let label = b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024";
        let mut okm = [0u8; 96];
        Hkdf::<Sha256>::new(None, &secret)
            .expand(label, &mut okm)
            .expect("valid output length");

        pqxdh_secret_cases.push(json!({
            "secret_input": hex(&secret),
            "dh1": hex(&dh1),
            "dh2": hex(&dh2),
            "dh3": hex(&dh3),
            "dh4": hex(&dh4),
            "kyber_shared_secret": hex(&kyber_ss),
            "kyber_ciphertext": hex(&kyber_ct),
            "root_key": hex(&okm[0..32]),
            "chain_key": hex(&okm[32..64]),
            "pqr_key": hex(&okm[64..96]),
        }));
    }

    json!({
        "chain-key": chain_key_cases,
        "message-keys": message_keys_cases,
        "root-key": root_key_cases,
        "pqxdh-secret": pqxdh_secret_cases,
    })
}
