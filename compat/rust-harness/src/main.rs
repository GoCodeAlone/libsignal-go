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
//! `fingerprint`.
//!
//! The behavioral contract is the v0.91.0 upstream source. Most domains call
//! the genuine public API directly. The `hkdf` domain reproduces the chain
//! key / root key / message key / pqxdh-secret derivations, which are
//! `pub(crate)` upstream, against the same pinned crate versions (`hkdf`,
//! `hmac`, `sha2`) so the bytes match upstream exactly.

use std::io::{self, BufRead, Write};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use sha2::Sha256;

use libsignal_protocol::{
    kem, Fingerprint, IdentityKey, KeyPair, KyberPayload, PreKeySignalMessage, PrivateKey,
    PublicKey, SenderKeyDistributionMessage, SenderKeyMessage, SignalMessage,
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
        other => {
            return Err(format!(
                "unknown domain {other:?}; expected curve|kem-decaps|hkdf|messages|fingerprint"
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

        other => Err(format!("unknown method {other:?}")),
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
