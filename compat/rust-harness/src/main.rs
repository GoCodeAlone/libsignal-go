//
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Rust compatibility harness for the pure-Go libsignal port.
//!
//! Wraps upstream `libsignal-protocol` pinned to tag v0.91.0 (see ADR 0001:
//! the pin is v0.91.0, NOT v0.91.1) and exposes two modes:
//!
//!   * `gen-vectors <domain>` — prints a deterministic JSON test-vector batch
//!     to stdout. Output is seeded with a fixed `rand_chacha` seed recorded in
//!     the batch header, so re-running produces byte-identical vectors.
//!   * `interop` — a line-delimited JSON-RPC loop over stdin/stdout. Each input
//!     line is one request object `{"method": "...", "params": {...}}`; each
//!     output line is one response. Unknown methods produce an error response,
//!     never a crash, and the loop continues.
//!
//! Domains for `gen-vectors`: `curve`, `kem-decaps`, `hkdf`, `messages`,
//! `fingerprint`, `groups`.
//!
//! The behavioral contract is the v0.91.0 upstream source. Most domains call
//! the genuine public API directly. The `hkdf` domain reproduces the chain
//! key / root key / message key / pqxdh-secret derivations, which are
//! `pub(crate)` upstream, against the same pinned crate versions (`hkdf`,
//! `hmac`, `sha2`) so the bytes match upstream exactly.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::time::SystemTime;

use futures_util::FutureExt;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{Rng as _, SeedableRng, TryRngCore as _};
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use sha2::Sha256;

use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt, kem, message_decrypt,
    message_encrypt, process_prekey_bundle, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
    sealed_sender_multi_recipient_encrypt, Aci, CiphertextMessage, CiphertextMessageType,
    ContentHint, DeviceId, Fingerprint, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemSenderKeyStore, InMemSignalProtocolStore, KeyPair, KyberPayload,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey,
    SealedSenderV2SentMessage, SenderCertificate, SenderKeyDistributionMessage, SenderKeyMessage,
    SenderKeyRecord, ServerCertificate, ServiceId, SessionRecord, SessionStore, SignalMessage,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    UnidentifiedSenderMessageContent,
};

/// Fixed seed for the deterministic CSPRNG. Recorded in every batch header so a
/// consumer can reproduce the vectors. Chosen arbitrarily but never changed.
const VECTOR_SEED: u64 = 0x5163_6e61_6c47_6f00; // "SignalGo\0"-ish, stable.

/// Builds the seeded CSPRNG used for all vector generation. ChaCha20 with a
/// fixed seed is reproducible and satisfies the `rand_core` 0.9 `CryptoRng`
/// bounds the libsignal APIs require (so it can drive key generation and the
/// XEdDSA signing nonce directly).
fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(VECTOR_SEED)
}

/// An RNG that replays a fixed byte buffer, then errors if drained.
///
/// XEdDSA signing draws a 64-byte nonce from its `csprng` (see
/// curve25519::PrivateKey::calculate_signature). To let the Go consumer
/// reproduce a signature byte-for-byte, the curve vectors record that exact
/// nonce: we draw 64 bytes from the seeded stream, emit them, then sign through
/// a FixedRng over those same bytes. The Go test feeds the identical 64 bytes
/// to its signer's `io.Reader`.
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

// rand_core 0.9 CryptoRng is a marker trait. The fixed bytes here are drawn
// from a CSPRNG upstream, so asserting the marker is sound for test-vector use.
impl rand_core::CryptoRng for FixedRng {}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("gen-vectors") => match args.get(2).map(String::as_str) {
            Some(domain) => gen_vectors(domain),
            None => Err("gen-vectors requires a <domain> argument".to_string()),
        },
        Some("interop") => {
            interop_loop();
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown mode {other:?}; expected gen-vectors|interop"
        )),
        None => Err("usage: rust-harness <gen-vectors <domain>|interop>".to_string()),
    };
    if let Err(msg) = result {
        eprintln!("rust-harness: {msg}");
        std::process::exit(2);
    }
}

// ---------------------------------------------------------------------------
// gen-vectors
// ---------------------------------------------------------------------------

/// Number of cases each generator emits. Sized so the T12 consumption gate is
/// satisfied with headroom: hkdf needs >=20 per sub-domain, kem-decaps >=100.
const N_CURVE_SIGN: u32 = 24;
const N_CURVE_ECDH: u32 = 24;
const N_KEM: u32 = 128;
const N_HKDF_PER_SUBDOMAIN: u32 = 24;
const N_MESSAGES_SETS: u32 = 8;
const N_FINGERPRINT_PAIRS: u32 = 8;
const N_SESSIONS_NO_OPK: u32 = 24;
const N_GROUPS_SETS: u32 = 8;
const N_GROUPS_DERIVATIONS: u32 = 24;
const N_SEALEDSENDER_CASES: u32 = 12;
const N_MLKEM_INCREMENTAL_CASES: u32 = 24;

fn gen_vectors(domain: &str) -> Result<(), String> {
    // Every batch carries a {domain, seed} header. Most domains add a flat
    // `cases` array; hkdf instead adds a `subdomains` object keyed by
    // sub-domain name (the T12 gate inspects `.subdomains | keys`).
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
        "messages" => {
            obj.insert("cases".into(), Value::Array(gen_messages()));
        }
        "fingerprint" => {
            obj.insert("cases".into(), Value::Array(gen_fingerprint()));
        }
        "sessions" => {
            obj.insert("cases".into(), Value::Array(gen_sessions()));
        }
        "groups" => {
            // `cases` carries the end-to-end cipher golden bytes; `derivations`
            // carries the byte-exact sender-key primitive KAT (chain-key ratchet
            // + senderMessageKey iv/cipher_key), pinned independently of the
            // cipher framing — the same pattern ratchet/ uses against hkdf.json.
            obj.insert("cases".into(), Value::Array(gen_groups()));
            obj.insert(
                "derivations".into(),
                Value::Array(gen_sender_key_derivations()),
            );
        }
        "sealedsender" => {
            obj.insert("cases".into(), Value::Array(gen_sealedsender()));
        }
        "mlkem-incremental" => {
            // Provenance note: pins the generating crate revisions and records
            // which libcrux backend produced the raw `encaps_state`. With
            // simd128/simd256 OFF (this harness depends on libcrux-ml-kem with
            // default-features=false + features=incremental/mlkem768/alloc),
            // libcrux always uses the PORTABLE backend, whose EncapsState i16
            // serialization is correct little-endian — so `encaps_state` (raw)
            // already equals `encaps_state_fixed` on every host. If a future
            // build enables a SIMD backend (NEON on aarch64, AVX2 on x86), the
            // raw field would carry the cryspen/libcrux#1275 byte-swap and would
            // differ from `encaps_state_fixed` — that is a backend difference,
            // NOT corruption or a regression. Regenerate (see README) if the
            // pinned revs below change.
            obj.insert(
                "_note".into(),
                json!({
                    "encaps_state_backend": "libcrux portable (simd128/simd256 disabled); raw == fixed on all hosts",
                    "libcrux_ml_kem": "0.0.8 (registry, =0.0.8 in compat/rust-harness/Cargo.toml; checksum-pinned in Cargo.lock)",
                    "spqr_reference": "1.5.1 (git tag v1.5.1, rev f2589fef855c10f39d72634dab3d14654dd410bf; issue-1275 fix reproduced inline in gen_mlkem_incremental since SPQR's wrapper is pub(crate))",
                    "issue_1275": "https://github.com/cryspen/libcrux/issues/1275 — SIMD-backend EncapsState i16 endianness",
                }),
            );
            obj.insert("cases".into(), Value::Array(gen_mlkem_incremental()));
        }
        "spqr-chunks" => {
            // Golden BE-u16 chunk vectors + GF16 mul/div triples captured from
            // the SPQR v1.5.1 crate (test-utils feature). Pins the big-endian
            // point/coefficient wire serialization that the erasure property
            // test cannot see (encoder+decoder share their convention).
            obj.insert(
                "_note".into(),
                json!({
                    "spqr_reference": "1.5.1 (git tag v1.5.1, rev f2589fef855c10f39d72634dab3d14654dd410bf, test-utils feature)",
                    "endianness": "GF16 points/coefficients serialize BIG-endian u16 (encoding/polynomial.rs Pt::serialize, Poly::serialize, chunk_at) — OPPOSITE of the KEM EncapsState LE-i16",
                    "gf_poly": "0x1100b (x^16+x^12+x^3+x+1)",
                }),
            );
            obj.insert("cases".into(), Value::Array(gen_spqr_chunks()));
            obj.insert("gf_triples".into(), Value::Array(gen_gf16_triples()));
        }
        other => {
            return Err(format!(
                "unknown domain {other:?}; \
                 expected curve|kem-decaps|hkdf|messages|fingerprint|sessions|groups|sealedsender|mlkem-incremental|spqr-chunks"
            ));
        }
    };
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &batch).map_err(|e| e.to_string())?;
    writeln!(out).map_err(|e| e.to_string())?;
    Ok(())
}

/// curve domain: XEdDSA sign/verify with a deterministic 64-byte nonce (the
/// nonce is drawn from the seeded CSPRNG, making the signature reproducible)
/// and X25519 ECDH agreement.
fn gen_curve() -> Vec<Value> {
    use rand_core::RngCore;
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for i in 0..N_CURVE_SIGN {
        let signer = KeyPair::generate(&mut rng);
        let message: Vec<u8> = (0..(8 + i as usize))
            .map(|j| (i as u8).wrapping_add(j as u8))
            .collect();
        // Draw the 64-byte signing nonce explicitly so it can be recorded and
        // replayed by the Go consumer, then sign through a FixedRng over it.
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

/// kem-decaps domain: (pk, sk, ct, ss) quadruples. Generate a Kyber1024 key
/// pair, encapsulate to it, and decapsulate; record that the encapsulated and
/// decapsulated shared secrets match.
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

// --- hkdf domain: reproduces the pub(crate) ratchet derivations exactly. ---

/// `ChainKey::calculate_base_material`: HMAC-SHA256(chain_key, seed).
fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

/// hkdf domain. Four required sub-domains, each matching the v0.91.0 source.
///
/// chain-key: next chain key = HMAC-SHA256(chain_key, [0x02]).
///
/// message-keys: HKDF-SHA256(ikm=HMAC-SHA256(chain_key,[0x01]), salt=None,
/// info="WhisperMessageKeys") -> 32B cipher_key || 32B mac_key || 16B iv.
///
/// root-key: new shared = ECDH; HKDF-SHA256(ikm=shared, salt=root_key,
/// info="WhisperRatchet") -> 32B next_root || 32B chain_key.
///
/// pqxdh-secret: 0xFF*32 || DH1 || DH2 || DH3 || DH4 || kyber_ss, then
/// HKDF-SHA256(ikm=secret, salt=None, info=<X25519/Kyber label>) -> 32B root ||
/// 32B chain || 32B pqr.
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
        let identity = KeyPair::generate(&mut rng); // alice identity
        let base = KeyPair::generate(&mut rng); // alice base
        let their_identity = KeyPair::generate(&mut rng);
        let their_signed_pre = KeyPair::generate(&mut rng);
        let their_one_time = KeyPair::generate(&mut rng);
        let their_kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        // X3DH agreements, in the upstream order (see ratchet::initialize_alice_session).
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

/// messages domain: golden serialized bytes for the four wire message types,
/// with the full input parameters recorded so the Go consumer can both
/// deserialize the bytes (field equality) and re-serialize from the same
/// inputs (byte equality). Each set varies its inputs via the loop index.
fn gen_messages() -> Vec<Value> {
    use rand_core::RngCore;
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for i in 0..N_MESSAGES_SETS {
        let counter = 7 + i;
        let previous_counter = i;
        let chain_id = 9 + i;
        let iteration = 3 + i;
        let mac_key = [0x11u8 ^ (i as u8); 32];
        let ciphertext: Vec<u8> = (0..(16 + i as usize))
            .map(|j| (i as u8) ^ j as u8)
            .collect();

        let ratchet = KeyPair::generate(&mut rng);
        let sender_identity = IdentityKey::new(KeyPair::generate(&mut rng).public_key);
        let receiver_identity = IdentityKey::new(KeyPair::generate(&mut rng).public_key);

        // SignalMessage
        let signal = SignalMessage::new(
            4,
            &mac_key,
            None,
            ratchet.public_key,
            counter,
            previous_counter,
            &ciphertext,
            &sender_identity,
            &receiver_identity,
            &[],
        )
        .expect("SignalMessage::new");
        cases.push(json!({
            "type": "signal_message",
            "mac_key": hex(&mac_key),
            "ratchet_key": hex(&ratchet.public_key.serialize()),
            "counter": counter,
            "previous_counter": previous_counter,
            "ciphertext": hex(&ciphertext),
            "sender_identity": hex(&sender_identity.serialize()),
            "receiver_identity": hex(&receiver_identity.serialize()),
            "serialized": hex(signal.serialized()),
        }));

        // PreKeySignalMessage wrapping the SignalMessage above.
        let base = KeyPair::generate(&mut rng);
        let registration_id = 0x1234 + i;
        let pre_key_id = 31 + i;
        let signed_pre_key_id = 72 + i;
        let kyber_pre_key_id = 90 + i;
        // A v4 PreKeySignalMessage requires a Kyber payload (the message is
        // rejected on deserialize otherwise). Encapsulate to a fresh Kyber key
        // and carry the ciphertext.
        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let (_kyber_ss, kyber_ct) = kyber
            .public_key
            .encapsulate(&mut rng)
            .expect("kyber encapsulate");
        let prekey = PreKeySignalMessage::new(
            4,
            registration_id,
            Some(pre_key_id.into()),
            signed_pre_key_id.into(),
            Some(KyberPayload::new(kyber_pre_key_id.into(), kyber_ct.clone())),
            base.public_key,
            sender_identity,
            signal,
        )
        .expect("PreKeySignalMessage::new");
        cases.push(json!({
            "type": "prekey_signal_message",
            "registration_id": registration_id,
            "pre_key_id": pre_key_id,
            "signed_pre_key_id": signed_pre_key_id,
            "kyber_pre_key_id": kyber_pre_key_id,
            "kyber_ciphertext": hex(&kyber_ct),
            "base_key": hex(&base.public_key.serialize()),
            "serialized": hex(prekey.serialized()),
        }));

        // SenderKeyMessage (signed). The 64-byte signing nonce is recorded so
        // the Go consumer can re-sign byte-for-byte.
        let mut dist = [0u8; 16];
        rng.fill_bytes(&mut dist);
        let distribution_id = uuid::Uuid::from_bytes(dist);
        let signing = KeyPair::generate(&mut rng);
        let skm_ciphertext: Vec<u8> = (0..(12 + i as usize))
            .map(|j| 0xA0u8 ^ j as u8 ^ i as u8)
            .collect();
        let mut nonce = [0u8; 64];
        rng.fill_bytes(&mut nonce);
        let skm = SenderKeyMessage::new(
            3,
            distribution_id,
            chain_id,
            iteration,
            skm_ciphertext.clone().into_boxed_slice(),
            &mut FixedRng::new(nonce.to_vec()),
            &signing.private_key,
        )
        .expect("SenderKeyMessage::new");
        cases.push(json!({
            "type": "sender_key_message",
            "distribution_id": distribution_id.to_string(),
            "chain_id": chain_id,
            "iteration": iteration,
            "ciphertext": hex(&skm_ciphertext),
            "signing_private": hex(&signing.private_key.serialize()),
            "signing_public": hex(&signing.public_key.serialize()),
            "nonce": hex(&nonce),
            "serialized": hex(skm.serialized()),
        }));

        // SenderKeyDistributionMessage (unsigned; fully deterministic).
        let chain_key: Vec<u8> = (0..32u8).map(|b| b ^ i as u8).collect();
        let skdm = SenderKeyDistributionMessage::new(
            3,
            distribution_id,
            chain_id,
            iteration,
            chain_key.clone(),
            signing.public_key,
        )
        .expect("SenderKeyDistributionMessage::new");
        cases.push(json!({
            "type": "sender_key_distribution_message",
            "distribution_id": distribution_id.to_string(),
            "chain_id": chain_id,
            "iteration": iteration,
            "chain_key": hex(&chain_key),
            "signing_public": hex(&signing.public_key.serialize()),
            "serialized": hex(skdm.serialized()),
        }));
    }

    cases
}

/// fingerprint domain: stable display + scannable fingerprints for a fixed
/// identity-key pair, at the standard 5200 iterations.
fn gen_fingerprint() -> Vec<Value> {
    let mut rng = seeded_rng();
    let mut cases = Vec::new();
    let iterations = 5200u32;

    for i in 0..N_FINGERPRINT_PAIRS {
        let local = IdentityKey::new(KeyPair::generate(&mut rng).public_key);
        let remote = IdentityKey::new(KeyPair::generate(&mut rng).public_key);
        let local_id = format!("+1555000{:04}", 2 * i);
        let remote_id = format!("+1555000{:04}", 2 * i + 1);

        for version in [1u32, 2u32] {
            let fp = Fingerprint::new(
                version,
                iterations,
                local_id.as_bytes(),
                &local,
                remote_id.as_bytes(),
                &remote,
            )
            .expect("Fingerprint::new");
            let display = fp.display_string().expect("display_string");
            let scannable = fp.scannable.serialize().expect("scannable serialize");
            cases.push(json!({
                "version": version,
                "iterations": iterations,
                "local_id": local_id,
                "remote_id": remote_id,
                "local_key": hex(&local.serialize()),
                "remote_key": hex(&remote.serialize()),
                "display": display,
                "scannable": hex(&scannable),
            }));
        }
    }

    cases
}

/// sessions domain: PQXDH master-secret KATs for the NO-one-time-prekey case
/// (DH4 absent). The committed hkdf.json `pqxdh-secret` sub-domain only covers
/// the with-DH4 path; this fills that gap so the Go ratchet's DH4-optional
/// assembly is vector-locked against upstream without needing a live harness.
///
/// Each case omits the fourth agreement, exactly as upstream conditions it on
/// `Some(one_time_prekey)` (pqxdh.rs pqxdh_initiate / pqxdh_accept). The master
/// secret is therefore 0xFF*32 || DH1 || DH2 || DH3 || kyber_ss — one agreement
/// (32 bytes) shorter than the with-DH4 secret — then HKDF-expanded with the
/// X25519/Kyber label into 32B root || 32B chain || 32B pqr.
fn gen_sessions() -> Vec<Value> {
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for _ in 0..N_SESSIONS_NO_OPK {
        let identity = KeyPair::generate(&mut rng); // alice identity
        let base = KeyPair::generate(&mut rng); // alice base/ephemeral
        let their_identity = KeyPair::generate(&mut rng);
        let their_signed_pre = KeyPair::generate(&mut rng);
        let their_kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        // X3DH agreements WITHOUT the one-time pre-key (no DH4), upstream order.
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
        let (kyber_ss, kyber_ct) = their_kyber.public_key.encapsulate(&mut rng).expect("kyber");

        let mut secret = Vec::with_capacity(32 * 5);
        secret.extend_from_slice(&[0xFFu8; 32]); // discontinuity bytes
        secret.extend_from_slice(&dh1);
        secret.extend_from_slice(&dh2);
        secret.extend_from_slice(&dh3);
        // No DH4 — the one-time pre-key is absent.
        secret.extend_from_slice(kyber_ss.as_ref());

        let label = b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024";
        let mut okm = [0u8; 96];
        Hkdf::<Sha256>::new(None, &secret)
            .expand(label, &mut okm)
            .expect("valid output length");

        cases.push(json!({
            "case": "pqxdh-secret-no-one-time-prekey",
            "secret_input": hex(&secret),
            "dh1": hex(&dh1),
            "dh2": hex(&dh2),
            "dh3": hex(&dh3),
            "kyber_shared_secret": hex(&kyber_ss),
            "kyber_ciphertext": hex(&kyber_ct),
            "root_key": hex(&okm[0..32]),
            "chain_key": hex(&okm[32..64]),
            "pqr_key": hex(&okm[64..96]),
        }));
    }

    cases
}

/// groups domain: golden bytes for the full sender-key cipher. Each case
/// provisions a chain via create_sender_key_distribution_message (seeded, so
/// reproducible), records the *pre-encrypt* sending record, then group_encrypts
/// a plaintext through a recorded 64-byte signing nonce.
///
/// The Go consumer asserts both directions byte-for-byte:
///   - load `sender_record`, encrypt `plaintext` with `encrypt_nonce`, and the
///     resulting SenderKeyMessage must equal `skm`;
///   - process `skdm` into a fresh receiver store and group_decrypt `skm`, and
///     the plaintext must equal `plaintext`.
///
/// `sender_record` is the serialized SenderKeyRecord *before* encryption (the
/// chain at iteration 0), so Go starts from the identical state; `chain_id` and
/// the signing keys are surfaced redundantly for cross-checking.
fn gen_groups() -> Vec<Value> {
    use rand_core::RngCore;
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for i in 0..N_GROUPS_SETS {
        let sender_name = format!("+1555100{:04}", i);
        let device_id = DeviceId::new(1).expect("device id");
        let sender = ProtocolAddress::new(sender_name.clone(), device_id);

        let mut dist = [0u8; 16];
        rng.fill_bytes(&mut dist);
        let distribution_id = uuid::Uuid::from_bytes(dist);

        // Provision the chain (seeded -> reproducible) and capture both the SKDM
        // (receiver side) and the serialized sending record (pre-encrypt).
        let mut sender_store = InMemSenderKeyStore::new();
        let skdm = block_on(create_sender_key_distribution_message(
            &sender,
            distribution_id,
            &mut sender_store,
            &mut rng,
        ))
        .expect("create distribution");
        let pre_encrypt_record =
            load_record_bytes(&mut sender_store, &sender, distribution_id).expect("record present");
        let chain_id = skdm.chain_id().expect("chain id");
        let signing_public = skdm.signing_key().expect("signing key");

        // Encrypt through a recorded nonce so the SKM signature is reproducible.
        let plaintext: Vec<u8> = (0..(16 + i as usize))
            .map(|j| (0x5Au8) ^ (i as u8) ^ (j as u8))
            .collect();
        let mut nonce = [0u8; 64];
        rng.fill_bytes(&mut nonce);
        let skm = block_on(group_encrypt(
            &mut sender_store,
            &sender,
            distribution_id,
            &plaintext,
            &mut FixedRng::new(nonce.to_vec()),
        ))
        .expect("group encrypt");

        cases.push(json!({
            "sender_name": sender_name,
            "sender_device": 1,
            "distribution_id": hex(&dist),
            "chain_id": chain_id,
            "signing_public": hex(&signing_public.serialize()),
            "skdm": hex(skdm.serialized()),
            "sender_record": hex(&pre_encrypt_record),
            "plaintext": hex(&plaintext),
            "encrypt_nonce": hex(&nonce),
            "skm": hex(skm.serialized()),
        }));
    }

    cases
}

/// sealedsender domain: sealed sender v1 DECRYPT fixtures. A sealed message is
/// non-deterministic (random ephemeral key), so rather than pin bytes this
/// records, per case, the recipient's identity private key, the trust root, the
/// expected plaintext (the inner content), and the upstream-sealed v1 bytes. The
/// Go consumer decrypts `sealed` with `recipient_identity_private`, validates the
/// recovered sender certificate against `trust_root`, and checks the content
/// equals `expected_content`. This complements the live interop (which proves
/// both directions) with a committed, no-harness-needed decrypt check.
fn gen_sealedsender() -> Vec<Value> {
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for i in 0..N_SEALEDSENDER_CASES {
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let sender_identity = KeyPair::generate(&mut rng);
        let recipient_identity = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .expect("server cert");

        let expiration = Timestamp::from_epoch_millis(2_000_000_000_000 + i as u64);
        let sender_cert = SenderCertificate::new(
            format!("sender-{i}"),
            None,
            sender_identity.public_key,
            DeviceId::new(1).expect("device id"),
            expiration,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )
        .expect("sender cert");

        let content: Vec<u8> = (0..(16 + i as usize))
            .map(|j| (i as u8) ^ j as u8)
            .collect();
        let usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::Whisper,
            sender_cert,
            content.clone(),
            ContentHint::Resendable,
            Some(format!("group-{i}").into_bytes()),
        )
        .expect("usmc");

        // Seal v1: build a sender store, register the recipient identity, seal.
        let mut store = InMemSignalProtocolStore::new(
            IdentityKeyPair::new(
                IdentityKey::new(sender_identity.public_key),
                sender_identity.private_key,
            ),
            1,
        )
        .expect("store");
        let destination =
            ProtocolAddress::new(format!("recipient-{i}"), DeviceId::new(1).expect("dev"));
        store
            .save_identity(
                &destination,
                &IdentityKey::new(recipient_identity.public_key),
            )
            .now_or_never()
            .expect("sync")
            .expect("save identity");

        let sealed =
            sealed_sender_encrypt_from_usmc(&destination, &usmc, &store.identity_store, &mut rng)
                .now_or_never()
                .expect("sync")
                .expect("seal v1");

        cases.push(json!({
            "version": "v1",
            "recipient_identity_private": hex(&recipient_identity.private_key.serialize()),
            "recipient_identity_public": hex(&recipient_identity.public_key.serialize()),
            "trust_root": hex(&trust_root.public_key.serialize()),
            "expected_content": hex(&content),
            "expected_sender_uuid": format!("sender-{i}"),
            "sealed": hex(&sealed),
        }));
    }

    cases
}

// ---------------------------------------------------------------------------
// session interop: stateful PQXDH/Double Ratchet sessions over JSON-RPC
// ---------------------------------------------------------------------------
//
// The session methods drive the genuine upstream session API
// (process_prekey_bundle / message_encrypt / message_decrypt, all v0.91.0) so
// the pure-Go port can be checked role-for-role against it. Each party is an
// upstream InMemSignalProtocolStore kept alive across calls in a per-process
// registry keyed by an opaque string handle, so Go can run a whole conversation
// (handshake, then many encrypt/decrypt turns) against the same Rust peer.
//
// v0.91.0 sessions are PQXDH/v4 only (X3DH/v3 is removed upstream — see
// session.rs "X3DH no longer supported"). v0.91.0 ships the Sparse Post-Quantum
// Ratchet (spqr v1.5.1): initialize_{alice,bob}_session call
// spqr::initial_state(version V1, min_version V0) unconditionally — there is no
// UsePQRatchet flag at this tag — so sessions negotiate SPQR and the resulting
// v4 SignalMessages carry pq_ratchet bytes that the Go port mixes in (T28). The
// InMem stores never actually await, so the async API is driven synchronously
// via `now_or_never().expect("sync")`, matching upstream's own test support
// module.

thread_local! {
    /// Per-handle session state for the interop loop. Single-threaded: the loop
    /// reads one request at a time, so a RefCell is sufficient and there is no
    /// cross-thread sharing.
    static STORES: RefCell<HashMap<String, InMemSignalProtocolStore>> = RefCell::new(HashMap::new());
}

// --- mlkem-incremental domain: libcrux 0.0.8 incremental ML-KEM-768 (the SPQR
//     KEM), oracle 3 for the pure-Go internal/mlkem768incr incremental layer. ---

/// Byte sizes of the libcrux incremental ML-KEM-768 wire artifacts (K=3). These
/// are compile-time `const fn`s in libcrux; we assert them against the literals
/// the Go port hardcodes so a future libcrux bump that changes a size trips the
/// harness build rather than silently shifting the fixture.
const MLKEM_INCR_PK1_LEN: usize = 64; // ρ ‖ H(ek)
const MLKEM_INCR_PK2_LEN: usize = 1152; // ByteEncode₁₂(t̂)
const MLKEM_INCR_DK_LEN: usize = 2400; // compressed key pair (standard dk)
const MLKEM_INCR_CT1_LEN: usize = 960; // Compress₁₀(u)
const MLKEM_INCR_CT2_LEN: usize = 128; // Compress₄(v)
const MLKEM_INCR_STATE_LEN: usize = 2080; // r̂(3·512) ‖ error2(512) ‖ randomness(32)
const MLKEM_INCR_SS_LEN: usize = 32;

/// Reproduces SPQR's `potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275`
/// (SparsePostQuantumRatchet v1.5.1 src/incremental_mlkem768.rs), which is
/// `pub(crate)` in the spqr crate and so not callable here. libcrux's SIMD
/// backends (NEON/AVX2) serialize the per-coefficient i16s in `EncapsState` with
/// swapped endianness (cryspen/libcrux#1275); the portable backend is correct.
/// libcrux multiplexes on the host CPU at runtime, so the raw `encapsulate1`
/// state is host-dependent. We normalize it to the correct little-endian form
/// (what the portable backend — and the Go port — produce) so the committed
/// fixture is reproducible regardless of which backend built it.
///
/// Detection: the `error2` polynomial (state[1536..2048]) holds CBD η2 samples,
/// all in [-2, 2]. Read as little-endian i16, a correct encoding shows only
/// {0x0000, 0x0001, 0x0002, 0xFFFF(-1), 0xFFFE(-2)}; a byte-swapped one shows
/// {0x0100, 0x0200, 0xFEFF(-2 swapped)}. On the first decisive value we either
/// leave it (correct) or flip every i16 in state[0..len-32] (swapped); the
/// trailing 32 random bytes have no endianness and are never flipped.
fn mlkem_incr_fix_state_1275(es: &[u8]) -> Vec<u8> {
    assert_eq!(es.len(), MLKEM_INCR_STATE_LEN);
    const NEG1: i16 = 0xFFFFu16 as i16;
    const NEG2_GOOD: i16 = 0xFFFEu16 as i16;
    const NEG2_BAD: i16 = 0xFEFFu16 as i16;

    let error2 = &es[1536..MLKEM_INCR_STATE_LEN - 32];
    let mut flip = false;
    for c in error2.chunks_exact(2) {
        match i16::from_le_bytes([c[0], c[1]]) {
            0x0000 | NEG1 => {} // identical in either endianness; undecided
            0x0001 | 0x0002 | NEG2_GOOD => {
                flip = false;
                break;
            }
            0x0100 | 0x0200 | NEG2_BAD => {
                flip = true;
                break;
            }
            _ => break, // unexpected; treat as already-correct (SPQR warns + keeps)
        }
    }
    let mut out = es.to_vec();
    if flip {
        for i in (0..out.len() - 32).step_by(2) {
            out.swap(i, i + 1);
        }
    }
    out
}

/// mlkem-incremental domain: byte-exact KATs for the libcrux 0.0.8 incremental
/// ML-KEM-768 split (the KEM SPQR uses). Each case is generated from a fixed
/// 64-byte keygen seed and a fixed 32-byte encapsulation message (both drawn
/// from the seeded CSPRNG, so the batch is reproducible), exercising the full
/// incremental flow:
///
///   from_seed(seed) -> pk1(hdr) ‖ pk2(ek) ‖ sk(dk)
///   encapsulate1(pk1, m) -> ct1, encaps_state, ss
///   encapsulate2(encaps_state_fixed, pk2) -> ct2
///   decapsulate_compressed_key(dk, ct1, ct2) -> ss   (== encaps ss)
///
/// `encaps_state` is the raw state from this host's libcrux backend (possibly
/// issue-1275-swapped); `encaps_state_fixed` is the 1275-normalized state. On a
/// portable-backend host they are equal. The Go oracle test asserts (a) its own
/// EncapsState serializer == `encaps_state_fixed` and (b) its 1275 fix applied to
/// `encaps_state` == `encaps_state_fixed`, so both the codec and the fix are
/// pinned regardless of which backend produced the fixture.
fn gen_mlkem_incremental() -> Vec<Value> {
    use libcrux_ml_kem::mlkem768::incremental;

    // Lock the libcrux compile-time sizes to the literals the Go port assumes.
    assert_eq!(incremental::pk1_len(), MLKEM_INCR_PK1_LEN);
    assert_eq!(incremental::pk2_len(), MLKEM_INCR_PK2_LEN);
    assert_eq!(incremental::encaps_state_len(), MLKEM_INCR_STATE_LEN);
    assert_eq!(incremental::Ciphertext1::len(), MLKEM_INCR_CT1_LEN);
    assert_eq!(incremental::Ciphertext2::len(), MLKEM_INCR_CT2_LEN);

    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for _ in 0..N_MLKEM_INCREMENTAL_CASES {
        // `Rng::random` fills fixed-size byte arrays from the seeded CSPRNG
        // (matching the other generators' use of the in-scope `rand::Rng`).
        let seed: [u8; 64] = rng.random(); // KEY_GENERATION_SEED_SIZE
        let message: [u8; MLKEM_INCR_SS_LEN] = rng.random(); // SHARED_SECRET_SIZE

        let kp = incremental::KeyPairCompressedBytes::from_seed(seed);
        let pk1 = kp.pk1();
        let pk2 = kp.pk2();
        let dk = kp.sk();
        assert_eq!(dk.len(), MLKEM_INCR_DK_LEN);

        // pk1/pk2 must validate together (reconstructs t̂‖ρ and re-checks H).
        incremental::validate_pk_bytes(pk1, pk2).expect("pk1/pk2 consistent");

        let mut state = vec![0u8; MLKEM_INCR_STATE_LEN];
        let mut ss_enc = vec![0u8; MLKEM_INCR_SS_LEN];
        let ct1 =
            incremental::encapsulate1(pk1, message, &mut state, &mut ss_enc).expect("encapsulate1");
        let state_fixed = mlkem_incr_fix_state_1275(&state);

        let ct2 =
            incremental::encapsulate2((&state_fixed[..]).try_into().expect("state len 2080"), pk2);

        let ct1v = ct1.value;
        let ct2v = ct2.value;
        let ct1_obj = incremental::Ciphertext1 { value: ct1v };
        let ct2_obj = incremental::Ciphertext2 { value: ct2v };
        let ss_dec = incremental::decapsulate_compressed_key(dk, &ct1_obj, &ct2_obj);

        let matches = ss_enc.as_slice() == ss_dec.as_ref();

        cases.push(json!({
            "seed": hex(&seed),
            "message": hex(&message),
            "pk1": hex(pk1),
            "pk2": hex(pk2),
            "dk": hex(dk),
            "ct1": hex(&ct1v),
            "ct2": hex(&ct2v),
            "encaps_state": hex(&state),
            "encaps_state_fixed": hex(&state_fixed),
            "shared_secret": hex(&ss_enc),
            "decapsulated_matches": matches,
        }));
    }

    cases
}

// --- spqr-chunks domain: golden BE-u16 chunk vectors + GF16 mul/div triples
//     captured from SPQR v1.5.1 (test-utils), oracle leg (c) for T27 Slice B. ---

/// Number of golden chunk cases and GF16 triples to emit. Sized to cover the
/// literal-data path (low indices), the interpolation path (high indices), and a
/// realistic ek-sized message.
const N_SPQR_CHUNK_MESSAGES: usize = 6;
const N_GF16_TRIPLES: usize = 64;

/// spqr-chunks domain. For each fixed message, capture a set of `chunk_at(i)`
/// outputs from the genuine SPQR PolyEncoder — including indices within the
/// original data (literal points) and beyond it (interpolated points) — so the
/// Go port's chunk bytes are pinned to the crate's big-endian wire byte-for-byte.
fn gen_spqr_chunks() -> Vec<Value> {
    use spqr::encoding::polynomial::PolyEncoder;
    use spqr::encoding::Encoder;

    let mut rng = seeded_rng();
    // Message lengths exercising: tiny, sub-chunk, multi-chunk, and the
    // 1152-byte incremental-ML-KEM ek (the real payload SPQR chunks).
    let lengths = [2usize, 10, 32, 64, 320, 1152];
    let mut cases = Vec::new();
    for (mi, &len) in lengths.iter().take(N_SPQR_CHUNK_MESSAGES).enumerate() {
        let mut msg = vec![0u8; len];
        for b in msg.iter_mut() {
            *b = rng.random(); // in-scope rand::Rng fills bytes from the seeded CSPRNG
        }

        // Indices spanning the literal-data range and well past it (forcing the
        // encoder's Points→Polys interpolation transition).
        let max_data_chunks = (len / 32) + 1;
        let mut indices: Vec<u16> = Vec::new();
        for i in 0..(max_data_chunks as u16 + 2) {
            indices.push(i);
        }
        // A few high indices to pin interpolated points.
        for k in 0..4u16 {
            indices.push(max_data_chunks as u16 * 3 + k);
        }

        let mut chunks = Vec::new();
        for &idx in &indices {
            // A fresh encoder per chunk keeps each capture independent of the
            // lazy Points→Polys state transition order.
            let mut enc = PolyEncoder::encode_bytes(&msg).expect("encode_bytes");
            let c = enc.chunk_at(idx);
            chunks.push(json!({
                "index": c.index,
                "data": hex(&c.data),
            }));
        }

        cases.push(json!({
            "msg_index": mi,
            "message": hex(&msg),
            "chunks": chunks,
        }));
    }
    cases
}

/// GF(2^16) mul/div KAT triples from the genuine SPQR GF16 (POLY=0x1100b). Each
/// triple records a, b, a*b and (when b != 0) a/b, so the Go field is pinned to
/// the crate's exact arithmetic independently of the property tests.
fn gen_gf16_triples() -> Vec<Value> {
    use spqr::encoding::gf::GF16;

    let mut rng = seeded_rng();
    let mut out = Vec::new();
    for _ in 0..N_GF16_TRIPLES {
        let a = rng.random::<u16>();
        let b = rng.random::<u16>();
        let prod = (GF16::new(a) * GF16::new(b)).value;
        let mut case = json!({
            "a": a,
            "b": b,
            "product": prod,
        });
        if b != 0 {
            let quot = (GF16::new(a) / GF16::new(b)).value;
            case.as_object_mut()
                .unwrap()
                .insert("quotient".into(), json!(quot));
        }
        out.push(case);
    }
    out
}

/// The interop CSPRNG. Session key generation and Kyber encapsulation must use a
/// real CSPRNG (the handshake is not vector-locked here — agreement is checked
/// by decrypting, not by byte equality), so this draws from the OS. rand 0.9's
/// fallible OsRng is wrapped via `unwrap_err()` into the infallible RngCore +
/// CryptoRng the libsignal session APIs require, matching upstream test support.
fn interop_rng() -> rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

/// Fixed device id for every interop address. Conversations are pairwise and the
/// address name carries identity, so a constant device id keeps addresses simple
/// and deterministic.
fn fixed_device_id() -> DeviceId {
    DeviceId::new(1).expect("1 is a valid device id")
}

fn protocol_address(name: &str) -> ProtocolAddress {
    ProtocolAddress::new(name.to_string(), fixed_device_id())
}

/// Runs a fresh store through a closure and returns its result. Creating a store
/// generates a new identity key pair and registration id.
fn with_new_store<T>(handle: &str, f: impl FnOnce(&mut InMemSignalProtocolStore) -> T) -> T {
    let mut rng = interop_rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    // Valid registration ids fit in 14 bits.
    let registration_id: u32 = (rng.random::<u16>() & 0x3FFF) as u32;
    let mut store = InMemSignalProtocolStore::new(identity, registration_id).expect("create store");
    let out = f(&mut store);
    STORES.with(|m| {
        m.borrow_mut().insert(handle.to_string(), store);
    });
    out
}

/// Borrows an existing store mutably for the duration of `f`. Errors if the
/// handle is unknown so a misuse surfaces as an RPC error, not a panic.
fn with_store<T>(
    handle: &str,
    f: impl FnOnce(&mut InMemSignalProtocolStore) -> Result<T, String>,
) -> Result<T, String> {
    STORES.with(|m| {
        let mut map = m.borrow_mut();
        let store = map
            .get_mut(handle)
            .ok_or_else(|| format!("unknown session handle {handle:?}"))?;
        f(store)
    })
}

/// session.create-prekey-bundle — generate a recipient's (Bob's) key material in
/// a fresh store under `handle`, register the pre-keys, and return the bundle
/// fields the initiator needs. `with_one_time` controls whether a one-time
/// pre-key is included (its absence exercises the optional-DH4 PQXDH path).
///
/// Params: { handle: str, with_one_time: bool }
/// Result: { registration_id, device_id, signed_pre_key_id, signed_pre_key_public,
///           signed_pre_key_signature, kyber_pre_key_id, kyber_pre_key_public,
///           kyber_pre_key_signature, identity_key, pre_key_id?, pre_key_public? }
fn session_create_prekey_bundle(params: &Value) -> Result<Value, String> {
    let handle = param_str(params, "handle")?;
    let with_one_time = params
        .get("with_one_time")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    with_new_store(&handle, |store| {
        let mut rng = interop_rng();

        let signed_pre_key_pair = KeyPair::generate(&mut rng);
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        let identity = store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")
            .map_err(|e| e.to_string())?;
        let registration_id = store
            .get_local_registration_id()
            .now_or_never()
            .expect("sync")
            .map_err(|e| e.to_string())?;

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity
            .private_key()
            .calculate_signature(&signed_pre_key_public, &mut rng)
            .map_err(|e| e.to_string())?;

        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let kyber_pre_key_signature = identity
            .private_key()
            .calculate_signature(&kyber_pre_key_public, &mut rng)
            .map_err(|e| e.to_string())?;

        // Deterministic small ids; the conversation is pairwise so collisions
        // across handles do not matter (each handle owns its own store).
        let signed_pre_key_id: u32 = 1;
        let kyber_pre_key_id: u32 = 1;
        let pre_key_id: u32 = 1;

        // Register signed + kyber pre-keys.
        store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    SignedPreKeyId::from(signed_pre_key_id),
                    Timestamp::from_epoch_millis(42),
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")
            .map_err(|e| e.to_string())?;
        store
            .save_kyber_pre_key(
                kyber_pre_key_id.into(),
                &KyberPreKeyRecord::new(
                    KyberPreKeyId::from(kyber_pre_key_id),
                    Timestamp::from_epoch_millis(43),
                    &kyber_pre_key_pair,
                    &kyber_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")
            .map_err(|e| e.to_string())?;

        let mut result = json!({
            "registration_id": registration_id,
            "device_id": u32::from(fixed_device_id()),
            "signed_pre_key_id": signed_pre_key_id,
            "signed_pre_key_public": hex(&signed_pre_key_pair.public_key.serialize()),
            "signed_pre_key_signature": hex(&signed_pre_key_signature),
            "kyber_pre_key_id": kyber_pre_key_id,
            "kyber_pre_key_public": hex(&kyber_pre_key_pair.public_key.serialize()),
            "kyber_pre_key_signature": hex(&kyber_pre_key_signature),
            "identity_key": hex(&identity.identity_key().serialize()),
        });
        let obj = result.as_object_mut().expect("object");

        if with_one_time {
            let pre_key_pair = KeyPair::generate(&mut rng);
            store
                .save_pre_key(
                    pre_key_id.into(),
                    &PreKeyRecord::new(PreKeyId::from(pre_key_id), &pre_key_pair),
                )
                .now_or_never()
                .expect("sync")
                .map_err(|e| e.to_string())?;
            obj.insert("pre_key_id".into(), json!(pre_key_id));
            obj.insert(
                "pre_key_public".into(),
                json!(hex(&pre_key_pair.public_key.serialize())),
            );
        }

        Ok(result)
    })
}

/// session.process-bundle-as-alice — the initiator side. Creates a fresh Alice
/// store under `handle`, assembles a PreKeyBundle from the supplied fields (a
/// peer/Bob's, produced by Go or by session.create-prekey-bundle), and runs
/// process_prekey_bundle so the store holds an unacknowledged Alice session
/// toward `remote_name`.
///
/// Params: { handle, remote_name, registration_id, device_id, identity_key,
///           signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature,
///           kyber_pre_key_id, kyber_pre_key_public, kyber_pre_key_signature,
///           pre_key_id?, pre_key_public? }
/// Result: { ok: true }
fn session_process_bundle_as_alice(params: &Value) -> Result<Value, String> {
    let handle = param_str(params, "handle")?;
    let remote_name = param_str(params, "remote_name")?;
    let bundle = build_prekey_bundle(params)?;

    // Create Alice's store (fresh identity + registration id), then run the
    // handshake against it. process_prekey_bundle needs the store's own identity,
    // which is generated when the store is created.
    with_new_store(&handle, |store| {
        let mut rng = interop_rng();
        let remote = protocol_address(&remote_name);
        // process_prekey_bundle at v0.91.0 takes no local_address.
        process_prekey_bundle(
            &remote,
            &mut store.session_store,
            &mut store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;
        Ok(json!({ "ok": true }))
    })
}

/// Builds an upstream PreKeyBundle from the JSON fields of a peer's bundle.
fn build_prekey_bundle(params: &Value) -> Result<PreKeyBundle, String> {
    let registration_id = param_u32(params, "registration_id")?;
    let identity_key =
        IdentityKey::decode(&param_bytes(params, "identity_key")?).map_err(|e| e.to_string())?;
    let signed_pre_key_id = param_u32(params, "signed_pre_key_id")?;
    let signed_pre_key_public =
        PublicKey::deserialize(&param_bytes(params, "signed_pre_key_public")?)
            .map_err(|e| e.to_string())?;
    let signed_pre_key_signature = param_bytes(params, "signed_pre_key_signature")?;
    let kyber_pre_key_id = param_u32(params, "kyber_pre_key_id")?;
    let kyber_pre_key_public =
        kem::PublicKey::deserialize(&param_bytes(params, "kyber_pre_key_public")?)
            .map_err(|e| e.to_string())?;
    let kyber_pre_key_signature = param_bytes(params, "kyber_pre_key_signature")?;

    // The one-time pre-key is optional (absent exercises the no-DH4 path).
    let pre_key = match (params.get("pre_key_id"), params.get("pre_key_public")) {
        (Some(id), Some(_)) if !id.is_null() => {
            let id = param_u32(params, "pre_key_id")?;
            let public = PublicKey::deserialize(&param_bytes(params, "pre_key_public")?)
                .map_err(|e| e.to_string())?;
            Some((PreKeyId::from(id), public))
        }
        _ => None,
    };

    PreKeyBundle::new(
        registration_id,
        fixed_device_id(),
        pre_key,
        SignedPreKeyId::from(signed_pre_key_id),
        signed_pre_key_public,
        signed_pre_key_signature,
        KyberPreKeyId::from(kyber_pre_key_id),
        kyber_pre_key_public,
        kyber_pre_key_signature,
        identity_key,
    )
    .map_err(|e| e.to_string())
}

/// session.encrypt — encrypt `plaintext` from `handle`'s store toward
/// `remote_name` via the genuine message_encrypt. Returns the ciphertext type
/// (2 = Whisper/SignalMessage, 3 = PreKey/PreKeySignalMessage) and the
/// serialized bytes for the peer to decrypt.
///
/// Params: { handle, remote_name, plaintext: hex }
/// Result: { type: u8, serialized: hex }
fn session_encrypt(params: &Value) -> Result<Value, String> {
    let handle = param_str(params, "handle")?;
    let remote_name = param_str(params, "remote_name")?;
    let plaintext = param_bytes(params, "plaintext")?;

    with_store(&handle, |store| {
        let mut rng = interop_rng();
        let remote = protocol_address(&remote_name);
        let local = protocol_address("self");
        let ct = message_encrypt(
            &plaintext,
            &remote,
            &local,
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;
        Ok(json!({
            "type": ct.message_type() as u8,
            "serialized": hex(ct.serialize()),
        }))
    })
}

/// session.decrypt — decrypt a ciphertext into `handle`'s store from
/// `remote_name`. `type` selects the wire form (2 = Whisper, 3 = PreKey);
/// message_decrypt establishes the session from a PreKey message if needed.
///
/// Params: { handle, remote_name, type: u8, serialized: hex }
/// Result: { plaintext: hex }
fn session_decrypt(params: &Value) -> Result<Value, String> {
    let handle = param_str(params, "handle")?;
    let remote_name = param_str(params, "remote_name")?;
    let msg_type = param_u32(params, "type")? as u8;
    let serialized = param_bytes(params, "serialized")?;

    let ciphertext = match CiphertextMessageType::try_from(msg_type) {
        Ok(CiphertextMessageType::Whisper) => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(serialized.as_slice()).map_err(|e| e.to_string())?,
        ),
        Ok(CiphertextMessageType::PreKey) => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(serialized.as_slice()).map_err(|e| e.to_string())?,
        ),
        _ => {
            return Err(format!(
                "session.decrypt: unsupported ciphertext type {msg_type}"
            ))
        }
    };

    with_store(&handle, |store| {
        let mut rng = interop_rng();
        let remote = protocol_address(&remote_name);
        let local = protocol_address("self");
        let plaintext = message_decrypt(
            &ciphertext,
            &remote,
            &local,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;
        Ok(json!({ "plaintext": hex(&plaintext) }))
    })
}

/// Byte-exact KAT for the sender-key primitives, reproduced from the v0.91.0
/// source (sender_keys.rs SenderChainKey / SenderMessageKey, which are
/// `pub(crate)`) against the same pinned `hmac`/`hkdf`/`sha2` crates — the same
/// reproduction strategy the hkdf domain uses. For each random (iteration,
/// chain_key):
///
///   next_chain_key   = HMAC-SHA256(chain_key, [0x02])          // SenderChainKey::next
///   message_key_seed = HMAC-SHA256(chain_key, [0x01])          // sender_message_key
///   HKDF-SHA256(ikm=message_key_seed, salt=None, info="WhisperGroup") -> 48B
///       iv         = [0..16]
///       cipher_key = [16..48]                                  // SenderMessageKey::new
///
/// The Go consumer asserts groups.SenderChainKey.next().Seed() and the derived
/// senderMessageKey (iv/cipher_key) equal these bytes, pinning the primitive
/// independently of the SenderKeyMessage wire framing.
fn gen_sender_key_derivations() -> Vec<Value> {
    use rand_core::RngCore;
    let mut rng = seeded_rng();
    let mut cases = Vec::new();

    for i in 0..N_GROUPS_DERIVATIONS {
        let mut chain_key = [0u8; 32];
        rng.fill_bytes(&mut chain_key);
        let iteration = i; // vary the recorded iteration across cases

        let next_chain_key = hmac_sha256(&chain_key, &[0x02u8]);
        let message_key_seed = hmac_sha256(&chain_key, &[0x01u8]);
        let mut okm = [0u8; 48];
        Hkdf::<Sha256>::new(None, &message_key_seed)
            .expand(b"WhisperGroup", &mut okm)
            .expect("valid output length");

        cases.push(json!({
            "iteration": iteration,
            "chain_key": hex(&chain_key),
            "next_chain_key": hex(&next_chain_key),
            "message_key_seed": hex(&message_key_seed),
            "iv": hex(&okm[0..16]),
            "cipher_key": hex(&okm[16..48]),
        }));
    }

    cases
}

/// Reads the serialized SenderKeyRecord for (sender, distribution_id) out of the
/// store. Used by gen_groups to snapshot the pre-encrypt sending state.
fn load_record_bytes(
    store: &mut InMemSenderKeyStore,
    sender: &ProtocolAddress,
    distribution_id: uuid::Uuid,
) -> Option<Vec<u8>> {
    let record = block_on(
        <InMemSenderKeyStore as libsignal_protocol::SenderKeyStore>::load_sender_key(
            store,
            sender,
            distribution_id,
        ),
    )
    .expect("load sender key");
    record.map(|r| r.serialize().expect("serialize record"))
}

// ---------------------------------------------------------------------------
// sealed sender interop (v1): seal / unseal via the genuine upstream API
// ---------------------------------------------------------------------------
//
// These methods are stateless w.r.t. the STORES registry: each call builds a
// throwaway InMemSignalProtocolStore from explicit hex key material so the Go
// test fully controls both identities. The USMC is passed pre-serialized (Go
// builds it with its own certs in T23), so the harness only deserializes,
// seals/unseals via sealed_sender_encrypt_from_usmc / sealed_sender_decrypt_to_usmc
// (genuine v0.91.0), and returns the recovered USMC bytes for Go to re-parse.
// v1 sealing draws a random ephemeral key, so interop is checked by decryptability
// (round-trip), not byte-equality.

/// Builds a throwaway InMemSignalProtocolStore owning the given identity private
/// key (registration id is irrelevant for sealed-sender v1, fixed at 1).
fn store_with_identity(identity_private: &[u8]) -> Result<InMemSignalProtocolStore, String> {
    let private = PrivateKey::deserialize(identity_private).map_err(|e| e.to_string())?;
    let public = private.public_key().map_err(|e| e.to_string())?;
    let identity = IdentityKeyPair::new(IdentityKey::new(public), private);
    InMemSignalProtocolStore::new(identity, 1).map_err(|e| e.to_string())
}

/// sealed.seal-v1 — seal a (pre-serialized) USMC to a single recipient via
/// sealed_sender_encrypt_from_usmc.
///
/// Params: { usmc: hex, sender_identity_private: hex, recipient_identity_public: hex }
/// Result: { sealed: hex }
fn sealed_seal_v1(params: &Value) -> Result<Value, String> {
    let usmc_bytes = param_bytes(params, "usmc")?;
    let sender_private = param_bytes(params, "sender_identity_private")?;
    let recipient_public = param_bytes(params, "recipient_identity_public")?;

    let usmc =
        UnidentifiedSenderMessageContent::deserialize(&usmc_bytes).map_err(|e| e.to_string())?;
    let mut store = store_with_identity(&sender_private)?;

    // Register the recipient's identity so the encrypt path can look it up.
    let recipient_identity = IdentityKey::decode(&recipient_public).map_err(|e| e.to_string())?;
    let destination = protocol_address("recipient");
    store
        .save_identity(&destination, &recipient_identity)
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;

    let mut rng = interop_rng();
    let sealed =
        sealed_sender_encrypt_from_usmc(&destination, &usmc, &store.identity_store, &mut rng)
            .now_or_never()
            .expect("sync")
            .map_err(|e| e.to_string())?;
    Ok(json!({ "sealed": hex(&sealed) }))
}

/// sealed.unseal — decrypt a sealed sender message (v1 or v2) to its USMC via
/// sealed_sender_decrypt_to_usmc, returning the recovered USMC bytes (Go
/// re-parses + validates the sender cert itself). The version is taken from the
/// message's leading byte by the upstream decoder.
///
/// Params: { sealed: hex, recipient_identity_private: hex }
/// Result: { usmc: hex }
fn sealed_unseal(params: &Value) -> Result<Value, String> {
    let sealed = param_bytes(params, "sealed")?;
    let recipient_private = param_bytes(params, "recipient_identity_private")?;

    let store = store_with_identity(&recipient_private)?;
    let usmc = sealed_sender_decrypt_to_usmc(&sealed, &store.identity_store)
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;
    Ok(json!({ "usmc": hex(usmc.serialized().map_err(|e| e.to_string())?) }))
}

/// sealed.seal-v2 — multi-recipient sealed sender v2 seal via the genuine
/// sealed_sender_multi_recipient_encrypt, then fan out each recipient's
/// ReceivedMessage. The harness OWNS the recipient identities: for each of
/// `num_recipients` it generates an identity + a full PQXDH bundle and runs
/// process_prekey_bundle so the sender's store holds a SessionRecord (with a
/// remote_registration_id, which the multi-recipient encoder requires) toward a
/// fresh ACI ServiceId address. It returns, per recipient, that recipient's
/// identity private key and its fanned-out ReceivedMessage bytes, so the Go test
/// can DecryptToUSMC each and validate. Mirrors the upstream multi-recipient
/// path; v2 sealing is randomized, so interop is checked by decryptability.
///
/// Params: { usmc: hex, sender_identity_private: hex, num_recipients: u32 }
/// Result: { recipients: [{ identity_private: hex, received: hex }] }
fn sealed_seal_v2(params: &Value) -> Result<Value, String> {
    let usmc_bytes = param_bytes(params, "usmc")?;
    let sender_private = param_bytes(params, "sender_identity_private")?;
    let num_recipients = param_u32(params, "num_recipients")?;
    if num_recipients == 0 {
        return Err("sealed.seal-v2: num_recipients must be >= 1".to_string());
    }

    let usmc =
        UnidentifiedSenderMessageContent::deserialize(&usmc_bytes).map_err(|e| e.to_string())?;
    let mut sender_store = store_with_identity(&sender_private)?;
    let mut rng = interop_rng();

    // Per recipient: generate identity + bundle, process it into the sender store
    // (creating a session w/ the registration id), and remember the address +
    // identity private key.
    let mut addresses: Vec<ProtocolAddress> = Vec::with_capacity(num_recipients as usize);
    let mut recipient_privates: Vec<Vec<u8>> = Vec::with_capacity(num_recipients as usize);
    for i in 0..num_recipients {
        let recipient_identity = IdentityKeyPair::generate(&mut rng);
        // A fresh ACI ServiceId; multi-recipient requires ServiceId-string names.
        let mut uuid = [0u8; 16];
        rand::Rng::fill(&mut rng, &mut uuid[..]);
        let aci = Aci::from_uuid_bytes(uuid);
        let address = ProtocolAddress::new(aci.service_id_string(), fixed_device_id());

        // Build the recipient's bundle in its own store, then process it as Alice
        // into the sender store so the sender has a session toward `address`.
        let registration_id: u32 = 1 + i; // small, within the 14-bit valid range
        let mut recipient_store =
            InMemSignalProtocolStore::new(recipient_identity, registration_id)
                .map_err(|e| e.to_string())?;
        let bundle = build_recipient_bundle(&mut recipient_store, registration_id, &mut rng)?;
        process_prekey_bundle(
            &address,
            &mut sender_store.session_store,
            &mut sender_store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;

        addresses.push(address);
        recipient_privates.push(recipient_identity.private_key().serialize().to_vec());
    }

    // Load each session record (now carrying the remote registration id).
    let mut sessions: Vec<SessionRecord> = Vec::with_capacity(addresses.len());
    for address in &addresses {
        let record = sender_store
            .session_store
            .load_session(address)
            .now_or_never()
            .expect("sync")
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no session for {address}"))?;
        sessions.push(record);
    }
    let address_refs: Vec<&ProtocolAddress> = addresses.iter().collect();
    let session_refs: Vec<&SessionRecord> = sessions.iter().collect();

    let sent = sealed_sender_multi_recipient_encrypt(
        &address_refs,
        &session_refs,
        std::iter::empty::<ServiceId>(),
        &usmc,
        &sender_store.identity_store,
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .map_err(|e| e.to_string())?;

    // Fan out each recipient's ReceivedMessage from the SentMessage.
    let parsed = SealedSenderV2SentMessage::parse(&sent).map_err(|e| e.to_string())?;
    let mut out_recipients = Vec::with_capacity(addresses.len());
    for (idx, address) in addresses.iter().enumerate() {
        let service_id = ServiceId::parse_from_service_id_string(address.name())
            .ok_or_else(|| format!("bad service id {address}"))?;
        let recipient = parsed
            .recipients
            .get(&service_id)
            .ok_or_else(|| format!("recipient {address} not in sent message"))?;
        let parts = parsed.received_message_parts_for_recipient(recipient);
        let received: Vec<u8> = parts.as_ref().concat();
        out_recipients.push(json!({
            "identity_private": hex(&recipient_privates[idx]),
            "received": hex(&received),
        }));
    }

    Ok(json!({ "recipients": out_recipients }))
}

/// Builds a full PQXDH PreKeyBundle (signed pre-key + Kyber pre-key + one-time
/// pre-key) for a recipient store, registering the keys so process_prekey_bundle
/// can later resolve them. A trimmed version of the session.create-prekey-bundle
/// flow, returning the typed PreKeyBundle directly for in-harness use.
fn build_recipient_bundle<R: rand::Rng + rand::CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    registration_id: u32,
    rng: &mut R,
) -> Result<PreKeyBundle, String> {
    let signed_pre_key_pair = KeyPair::generate(rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let pre_key_pair = KeyPair::generate(rng);

    let identity = store
        .get_identity_key_pair()
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key_public, rng)
        .map_err(|e| e.to_string())?;
    let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_pre_key_signature = identity
        .private_key()
        .calculate_signature(&kyber_pre_key_public, rng)
        .map_err(|e| e.to_string())?;

    let signed_pre_key_id: u32 = 1;
    let kyber_pre_key_id: u32 = 1;
    let pre_key_id: u32 = 1;

    store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                SignedPreKeyId::from(signed_pre_key_id),
                Timestamp::from_epoch_millis(42),
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;
    store
        .save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(
                KyberPreKeyId::from(kyber_pre_key_id),
                Timestamp::from_epoch_millis(43),
                &kyber_pre_key_pair,
                &kyber_pre_key_signature,
            ),
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;
    store
        .save_pre_key(
            pre_key_id.into(),
            &PreKeyRecord::new(PreKeyId::from(pre_key_id), &pre_key_pair),
        )
        .now_or_never()
        .expect("sync")
        .map_err(|e| e.to_string())?;

    PreKeyBundle::new(
        registration_id,
        fixed_device_id(),
        Some((PreKeyId::from(pre_key_id), pre_key_pair.public_key)),
        SignedPreKeyId::from(signed_pre_key_id),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        KyberPreKeyId::from(kyber_pre_key_id),
        kyber_pre_key_pair.public_key.clone(),
        kyber_pre_key_signature.to_vec(),
        *identity.identity_key(),
    )
    .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// interop: line-delimited JSON-RPC over stdin/stdout
// ---------------------------------------------------------------------------

fn interop_loop() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_request(&line);
        // One response object per line. Failures to write are fatal for the loop.
        if serde_json::to_writer(&mut stdout, &response).is_err() {
            break;
        }
        if writeln!(stdout).is_err() {
            break;
        }
        if stdout.flush().is_err() {
            break;
        }
    }
}

/// Parses and dispatches a single JSON-RPC request line. Any parse error,
/// unknown method, or operation failure becomes an error response object so the
/// loop never crashes. The dispatch table is intentionally small now (curve /
/// kem / message ops, plus `ping`); session/group/sealed methods are added in
/// later tasks via new match arms.
fn handle_request(line: &str) -> Value {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return error_response(Value::Null, &format!("invalid JSON: {e}")),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => return error_response(id, "missing \"method\" field"),
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    match dispatch(method, &params) {
        Ok(result) => json!({ "id": id, "ok": true, "result": result }),
        Err(msg) => error_response(id, &msg),
    }
}

fn error_response(id: Value, message: &str) -> Value {
    json!({ "id": id, "ok": false, "error": message })
}

/// Method dispatch. Returns the result value on success or an error string.
/// Unknown methods return `Err`, surfaced as an error response (not a crash).
fn dispatch(method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "ping" => Ok(json!({ "pong": true })),

        // curve.sign: { private_key: hex, message: hex } -> { signature, public_key }
        "curve.sign" => {
            let private_key = param_bytes(params, "private_key")?;
            let message = param_bytes(params, "message")?;
            let sk = PrivateKey::deserialize(&private_key).map_err(|e| e.to_string())?;
            let pk = sk.public_key().map_err(|e| e.to_string())?;
            // XEdDSA verifies regardless of the signing nonce, so cross-impl
            // agreement is checked via verify (not signature equality). The
            // seeded CSPRNG keeps even interop signatures reproducible.
            let mut rng = seeded_rng();
            let sig = sk
                .calculate_signature(&message, &mut rng)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "signature": hex(&sig), "public_key": hex(&pk.serialize()) }))
        }

        // curve.verify: { public_key: hex, message: hex, signature: hex } -> { verified }
        "curve.verify" => {
            let public_key = param_bytes(params, "public_key")?;
            let message = param_bytes(params, "message")?;
            let signature = param_bytes(params, "signature")?;
            let pk = PublicKey::deserialize(&public_key).map_err(|e| e.to_string())?;
            Ok(json!({ "verified": pk.verify_signature(&message, &signature) }))
        }

        // curve.agree: { private_key: hex, public_key: hex } -> { shared }
        "curve.agree" => {
            let private_key = param_bytes(params, "private_key")?;
            let public_key = param_bytes(params, "public_key")?;
            let sk = PrivateKey::deserialize(&private_key).map_err(|e| e.to_string())?;
            let pk = PublicKey::deserialize(&public_key).map_err(|e| e.to_string())?;
            let shared = sk.calculate_agreement(&pk).map_err(|e| e.to_string())?;
            Ok(json!({ "shared": hex(&shared) }))
        }

        // kem.decapsulate: { secret_key: hex, ciphertext: hex } -> { shared_secret }
        "kem.decapsulate" => {
            let secret_key = param_bytes(params, "secret_key")?;
            let ciphertext = param_bytes(params, "ciphertext")?;
            let sk = kem::SecretKey::deserialize(&secret_key).map_err(|e| e.to_string())?;
            let ss = sk
                .decapsulate(&ciphertext.into_boxed_slice())
                .map_err(|e| e.to_string())?;
            Ok(json!({ "shared_secret": hex(&ss) }))
        }

        // --- session methods (stateful; keyed by `handle`) ---
        "session.create-prekey-bundle" => session_create_prekey_bundle(params),
        "session.process-bundle-as-alice" => session_process_bundle_as_alice(params),
        "session.encrypt" => session_encrypt(params),
        "session.decrypt" => session_decrypt(params),

        // --- sealed sender (v1 + v2 seal; unseal handles v1 + v2) ---
        "sealed.seal-v1" => sealed_seal_v1(params),
        "sealed.seal-v2" => sealed_seal_v2(params),
        "sealed.unseal" => sealed_unseal(params),

        // message.parse_sender_key: { serialized: hex } -> { distribution_id, chain_id, iteration }
        "message.parse_sender_key" => {
            let serialized = param_bytes(params, "serialized")?;
            let msg =
                SenderKeyMessage::try_from(serialized.as_slice()).map_err(|e| e.to_string())?;
            Ok(json!({
                "distribution_id": msg.distribution_id().to_string(),
                "chain_id": msg.chain_id(),
                "iteration": msg.iteration(),
            }))
        }

        // group.create_distribution: { sender, device, distribution_id }
        //   -> { skdm, record }
        // Provisions a fresh sender-key chain in a one-shot store and returns the
        // distribution message plus the serialized SenderKeyRecord. The Go side
        // threads `record` back into group.encrypt; this keeps the harness
        // stateless (no record state survives between RPC lines).
        "group.create_distribution" => {
            let sender = param_address(params)?;
            let distribution_id = param_uuid(params, "distribution_id")?;
            let mut store = InMemSenderKeyStore::new();
            let mut rng = seeded_rng();
            let skdm = block_on(create_sender_key_distribution_message(
                &sender,
                distribution_id,
                &mut store,
                &mut rng,
            ))
            .map_err(|e| e.to_string())?;
            let record = load_record_hex(&mut store, &sender, distribution_id)?;
            Ok(json!({ "skdm": hex(skdm.serialized()), "record": record }))
        }

        // group.process_distribution: { sender, device, skdm, record? }
        //   -> { record }
        // Processes an SKDM into a store seeded from `record` (empty when absent)
        // and returns the updated serialized record.
        "group.process_distribution" => {
            let sender = param_address(params)?;
            let skdm_bytes = param_bytes(params, "skdm")?;
            let skdm = SenderKeyDistributionMessage::try_from(skdm_bytes.as_slice())
                .map_err(|e| e.to_string())?;
            let distribution_id = skdm.distribution_id().map_err(|e| e.to_string())?;
            let mut store = store_from_param(params, &sender, distribution_id)?;
            block_on(process_sender_key_distribution_message(
                &sender, &skdm, &mut store,
            ))
            .map_err(|e| e.to_string())?;
            let record = load_record_hex(&mut store, &sender, distribution_id)?;
            Ok(json!({ "record": record }))
        }

        // group.encrypt: { sender, device, distribution_id, record, plaintext }
        //   -> { skm, record }
        // Encrypts plaintext on the chain held in `record`, returning the signed
        // SenderKeyMessage and the advanced record.
        "group.encrypt" => {
            let sender = param_address(params)?;
            let distribution_id = param_uuid(params, "distribution_id")?;
            let plaintext = param_bytes(params, "plaintext")?;
            let mut store = store_from_param(params, &sender, distribution_id)?;
            let mut rng = seeded_rng();
            let skm = block_on(group_encrypt(
                &mut store,
                &sender,
                distribution_id,
                &plaintext,
                &mut rng,
            ))
            .map_err(|e| e.to_string())?;
            let record = load_record_hex(&mut store, &sender, distribution_id)?;
            Ok(json!({ "skm": hex(skm.serialized()), "record": record }))
        }

        // group.decrypt: { sender, device, distribution_id, record, skm }
        //   -> { plaintext, record }
        // Decrypts a SenderKeyMessage against the chain in `record`, returning the
        // plaintext and the advanced record.
        "group.decrypt" => {
            let sender = param_address(params)?;
            let distribution_id = param_uuid(params, "distribution_id")?;
            let skm_bytes = param_bytes(params, "skm")?;
            let mut store = store_from_param(params, &sender, distribution_id)?;
            let plaintext = block_on(group_decrypt(&skm_bytes, &mut store, &sender))
                .map_err(|e| e.to_string())?;
            let record = load_record_hex(&mut store, &sender, distribution_id)?;
            Ok(json!({ "plaintext": hex(&plaintext), "record": record }))
        }

        other => Err(format!("unknown method {other:?}")),
    }
}

/// Blocks on a future to completion using a minimal single-thread executor. The
/// upstream group functions are async over the (synchronous) in-memory store, so
/// the RPC dispatch drives them to completion here.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures::executor::block_on(fut)
}

/// Builds a ProtocolAddress from `sender` (name) and `device` (1..=255) params.
fn param_address(params: &Value) -> Result<ProtocolAddress, String> {
    let name = params
        .get("sender")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing string param \"sender\"".to_string())?;
    let device = params
        .get("device")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing integer param \"device\"".to_string())?;
    let device: u8 = device
        .try_into()
        .map_err(|_| format!("device {device} out of range 1..=255"))?;
    let device_id = DeviceId::new(device).map_err(|e| e.to_string())?;
    Ok(ProtocolAddress::new(name.to_string(), device_id))
}

/// Extracts a UUID param given as either a 32-hex-digit string (no dashes; the
/// raw 16 bytes) or a standard dashed UUID string. The Go side sends raw hex.
fn param_uuid(params: &Value, name: &str) -> Result<uuid::Uuid, String> {
    let s = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string param {name:?}"))?;
    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == 16 {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes);
            return Ok(uuid::Uuid::from_bytes(raw));
        }
    }
    uuid::Uuid::parse_str(s).map_err(|e| format!("param {name:?} is not a uuid: {e}"))
}

/// Builds an InMemSenderKeyStore pre-loaded with the SenderKeyRecord carried in
/// the optional `record` hex param (empty store when absent). Lets the RPCs stay
/// stateless by threading the record through each call.
fn store_from_param(
    params: &Value,
    sender: &ProtocolAddress,
    distribution_id: uuid::Uuid,
) -> Result<InMemSenderKeyStore, String> {
    let mut store = InMemSenderKeyStore::new();
    if let Some(s) = params.get("record").and_then(Value::as_str) {
        if !s.is_empty() {
            let bytes = hex::decode(s).map_err(|e| format!("param \"record\" is not hex: {e}"))?;
            let record = SenderKeyRecord::deserialize(&bytes).map_err(|e| e.to_string())?;
            block_on(
                <InMemSenderKeyStore as libsignal_protocol::SenderKeyStore>::store_sender_key(
                    &mut store,
                    sender,
                    distribution_id,
                    &record,
                ),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(store)
}

/// Reads the SenderKeyRecord for (sender, distribution_id) out of the store and
/// returns its serialized hex (empty string when the store has no record).
fn load_record_hex(
    store: &mut InMemSenderKeyStore,
    sender: &ProtocolAddress,
    distribution_id: uuid::Uuid,
) -> Result<String, String> {
    let record = block_on(
        <InMemSenderKeyStore as libsignal_protocol::SenderKeyStore>::load_sender_key(
            store,
            sender,
            distribution_id,
        ),
    )
    .map_err(|e| e.to_string())?;
    match record {
        Some(r) => Ok(hex(&r.serialize().map_err(|e| e.to_string())?)),
        None => Ok(String::new()),
    }
}

/// Extracts a named hex-string parameter and decodes it to bytes.
fn param_bytes(params: &Value, name: &str) -> Result<Vec<u8>, String> {
    let s = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string param {name:?}"))?;
    hex::decode(s).map_err(|e| format!("param {name:?} is not valid hex: {e}"))
}

/// Extracts a named plain-string parameter (not hex-decoded).
fn param_str(params: &Value, name: &str) -> Result<String, String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing string param {name:?}"))
}

/// Extracts a named unsigned-integer parameter.
fn param_u32(params: &Value, name: &str) -> Result<u32, String> {
    let n = params
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer param {name:?}"))?;
    u32::try_from(n).map_err(|_| format!("param {name:?} out of u32 range: {n}"))
}
