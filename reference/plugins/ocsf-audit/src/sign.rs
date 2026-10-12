// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Signing seam for the attestation. The hash chain (fingerprint /
// prev_event) works with no signer at all; a signer adds the
// `signatures` entry that makes the record verifiable against an
// identity, offline.
//
// `digital_signature.serialization_id` is how a record declares its
// signing envelope: 1 Flat, 2 JCS, 3 JWS, 4 COSE, 5 DSSE. Its
// `algorithm_id` 3 is ECDSA, a different enum from
// `fingerprint.algorithm_id`, where 3 is SHA-256: same number, different
// meaning.
//
// The record is DSSE (serialization_id 5): the signature is
// ECDSA-P256-SHA256 over the DSSE PAE of the event's canonical bytes, the
// same bytes the fingerprint covers (event with the attestation's uid /
// chain_uid / authority_uid / prev_event present, fingerprint / signatures
// absent). So the signature commits to the record's chain position, and a
// verifier needs exactly three things: the emitted JSON, the public key,
// and this file's documented PAE rule.

//! Canonical bytes, fingerprint, DSSE pre-authentication encoding and the
//! signer.

use base64::Engine as _;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// RFC 8785 (JCS) canonical serialization of an event.
///
/// This is what the fingerprint and the signer consume, so an independent
/// verifier can recompute the hash from the emitted JSON with any RFC 8785
/// library whose JSON parser keeps integers beyond 2^53 exact, without
/// depending on this serializer's internals. The rules:
///
/// * object keys sorted by UTF-16 code units (RFC 8785 section 3.2.3),
///   explicitly rather than via `serde_json`'s map order: a `BTreeMap`
///   sorts by UTF-8 bytes, which differs for keys outside the BMP, and a
///   workspace enabling `serde_json`'s `preserve_order` feature would
///   silently switch to insertion order;
/// * compact output, no insignificant whitespace;
/// * strings escaped per section 3.2.2.2, which is `serde_json`'s form:
///   two-character escapes where one exists, `\u00XX` for the other
///   control characters, nothing else escaped;
/// * floats in the ES6 `Number::toString` form of section 3.2.2.3
///   (`1.0` is `1`, `1e21` is `1e+21`, `1e-7` stays `1e-7`); integers in
///   their exact decimal digits, which is the same form for every integer
///   a double represents exactly. Integers beyond 2^53 (the engine's
///   nanosecond `epoch`, for one) are outside I-JSON's interoperable range,
///   and a verifier must parse them exactly rather than through a double,
///   as Python's `json` module does and JavaScript's does not;
/// * arrays serialized in the order given. Array order is semantic in
///   JSON (delegation chain, profiles), so the canonicalizer must not
///   sort them; instead, set-derived arrays (security labels, roles,
///   teams: `HashSet` / `MonotonicSet`, randomized iteration) are sorted
///   at build time in `ocsf.rs`, making the emitted event itself
///   canonical.
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(v, &mut out);
    out
}

/// Rebuild `v` with every object's keys in RFC 8785 order, so a pretty
/// printer walking the result prints the canonical order.
///
/// `serde_json::Map` keeps insertion order only under its `preserve_order`
/// feature, which a workspace build may turn on through feature
/// unification; without it the map sorts by UTF-8 bytes. The examples
/// print through this so their output matches the committed vectors
/// under either build. The hashed bytes never depend on it:
/// `canonical_bytes` sorts for itself.
pub fn canonical_order(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            entries.sort_unstable_by(|a, b| utf16_order(a.0, b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), canonical_order(v)))
                    .collect(),
            )
        },
        Value::Array(a) => Value::Array(a.iter().map(canonical_order).collect()),
        leaf => leaf.clone(),
    }
}

/// RFC 8785 section 3.2.3: property names compare as sequences of UTF-16
/// code units. Equal to code point order inside the BMP; a supplementary
/// character (surrogate pair, `0xD800..=0xDFFF`) sorts before `U+E000`
/// and above, where code point order would put it last.
fn utf16_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(m) => {
            out.push(b'{');
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            entries.sort_unstable_by(|a, b| utf16_order(a.0, b.0));
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Writing a `&str` into a `Vec` cannot fail.
                let _ = serde_json::to_writer(&mut *out, k);
                out.push(b':');
                write_canonical(v, out);
            }
            out.push(b'}');
        },
        Value::Array(a) => {
            out.push(b'[');
            for (i, el) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(el, out);
            }
            out.push(b']');
        },
        Value::Number(n) => match n.as_f64() {
            // `as_i64` / `as_u64` are `Some` only for numbers parsed or
            // built as integers; an integral float such as `2.0` takes the
            // ES6 path and comes out as `2`.
            Some(f) if n.as_i64().is_none() && n.as_u64().is_none() => write_es6_number(f, out),
            _ => out.extend_from_slice(n.to_string().as_bytes()),
        },
        leaf => out.extend_from_slice(leaf.to_string().as_bytes()),
    }
}

/// ES6 `Number::toString` (ECMA-262 section 7.1.12.1), the number form
/// RFC 8785 section 3.2.2.3 mandates. Ryu supplies the digits: the
/// shortest that round-trip, the closest of those to the value, ties to
/// even, which is the specification's choice of `s` and the one Rust's
/// `{:e}` departs from on an exact tie. The rest is the placement rule on
/// `n` (the decimal point's position relative to the digits) and `k` (the
/// digit count): plain digits up to 21 of them, a decimal point when it
/// lands inside or just before them, and the exponent form with an
/// explicit sign past either end.
fn write_es6_number(f: f64, out: &mut Vec<u8>) {
    if f == 0.0 {
        // Both signed zeros print as "0".
        out.push(b'0');
        return;
    }
    if f < 0.0 {
        out.push(b'-');
    }
    // Ryu prints `ddd.ddd` or `d.ddde±x`; recover the digit string and
    // `n` from either shape, then drop the zeros that carry no digits.
    let mut buf = ryu::Buffer::new();
    let printed = buf.format_finite(f.abs());
    let (mantissa, exponent) = printed
        .split_once('e')
        .map_or((printed, 0), |(m, e)| (m, e.parse::<i64>().unwrap_or(0)));
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits: Vec<u8> = int_part.bytes().chain(frac_part.bytes()).collect();
    let mut n = i64::try_from(int_part.len())
        .unwrap_or(i64::MAX)
        .saturating_add(exponent);
    let leading = digits.iter().take_while(|b| **b == b'0').count();
    digits.drain(..leading);
    n -= i64::try_from(leading).unwrap_or(0);
    while digits.last() == Some(&b'0') {
        digits.pop();
    }
    let k = i64::try_from(digits.len()).unwrap_or(i64::MAX);

    if k <= n && n <= 21 {
        out.extend_from_slice(&digits);
        out.extend(std::iter::repeat_n(
            b'0',
            usize::try_from(n - k).unwrap_or(0),
        ));
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(usize::try_from(n).unwrap_or(0));
        out.extend_from_slice(int);
        out.push(b'.');
        out.extend_from_slice(frac);
    } else if -6 < n && n <= 0 {
        out.extend_from_slice(b"0.");
        out.extend(std::iter::repeat_n(b'0', usize::try_from(-n).unwrap_or(0)));
        out.extend_from_slice(&digits);
    } else {
        if let Some((first, rest)) = digits.split_first() {
            out.push(*first);
            if !rest.is_empty() {
                out.push(b'.');
                out.extend_from_slice(rest);
            }
        }
        let e = n - 1;
        out.push(b'e');
        out.push(if e < 0 { b'-' } else { b'+' });
        out.extend_from_slice(e.abs().to_string().as_bytes());
    }
}

/// Compute the fingerprint value over canonical bytes (callers obtain
/// them via `canonical_bytes`).
///
/// Returns bare lowercase hex, no `sha256:` prefix. The algorithm is
/// declared by the sibling `fingerprint.algorithm_id` (3 = SHA-256) and
/// the representation by `fingerprint.encoding_id` (1 = Hex), so a
/// prefix inside `value` would both duplicate that and break a verifier
/// decoding `value` per `encoding_id`.
///
/// Per the `attestation` semantics, the emitter passes the canonical
/// bytes of the whole event with its `attestation_list[0]` present and
/// carrying `uid` / `chain_uid` / `authority_uid` / `prev_event`, but with
/// `fingerprint` and `signatures` absent. So the record's position in its
/// chain is inside the hashed input (a spliced or reordered record changes
/// its own fingerprint), and the signer consumes the same bytes.
pub fn fingerprint_value(canonical_bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut h = Sha256::new();
    h.update(canonical_bytes);

    // Hex-encoded by hand: sha2 0.11's digest returns a
    // `hybrid_array::Array`, which does not implement `LowerHex`.
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Reconstruct, from an emitted event, the exact bytes its fingerprint
/// and signature were computed over. This is the verifier rule as
/// running code:
///
/// 1. remove `attestation_list[0].fingerprint` and `.signatures` (the
///    schema's own exclusions);
/// 2. remove `unmapped.signature_b64` / `unmapped.signature_key_id`: the
///    signature bytes have no `digital_signature` home until
///    ocsf-schema#1709 lands, so they ride in `unmapped`, and being
///    derived from the hash they cannot be inside it (dropping `unmapped`
///    entirely if that leaves it empty, since an empty object was never
///    emitted pre-signing);
/// 3. canonicalize (JCS).
///
/// Then `fingerprint_value(bytes)` must equal the attestation's
/// `fingerprint.value`, and the DSSE signature verifies over
/// `dsse_pae(bytes)`.
pub fn signing_input(event: &Value) -> Vec<u8> {
    let mut ev = event.clone();
    if let Some(att) = ev
        .get_mut("attestation_list")
        .and_then(|l| l.get_mut(0))
        .and_then(Value::as_object_mut)
    {
        att.remove("fingerprint");
        att.remove("signatures");
    }
    let mut drop_unmapped = false;
    if let Some(un) = ev.get_mut("unmapped").and_then(Value::as_object_mut) {
        un.remove("signature_b64");
        un.remove("signature_key_id");
        drop_unmapped = un.is_empty();
    }
    if drop_unmapped && let Some(m) = ev.as_object_mut() {
        m.remove("unmapped");
    }
    canonical_bytes(&ev)
}

/// DSSE payload type for an OCSF event's canonical bytes.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.ocsf.event+json";

/// DSSE Pre-Authentication Encoding over `DSSE_PAYLOAD_TYPE`:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload`.
/// The signature is computed over these bytes, never the raw payload,
/// which is what makes the envelope resistant to cross-protocol reuse of
/// the same key.
pub fn dsse_pae(payload: &[u8]) -> Vec<u8> {
    let t = DSSE_PAYLOAD_TYPE.as_bytes();
    let mut out = Vec::with_capacity(payload.len() + t.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(t.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(t);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Result of signing: the detached signature bytes (base64 DER) and the
/// OCSF `digital_signature` descriptor to embed in
/// `attestation.signatures`. `key_id` (the JWKS `kid`) rides beside the
/// bytes at `unmapped.signature_key_id` until ocsf-schema#1709 gives both
/// a schema home.
pub struct Signed {
    /// The DER signature, base64 (standard alphabet, padded).
    pub signature: String,
    /// The JWKS `kid` of the signing key, when configured.
    pub key_id: Option<String>,
    /// The `digital_signature` descriptor: algorithm and serialization ids
    /// with their captions.
    pub digital_signature: serde_json::Value,
}

/// Produces the `signatures` entry for a record from its canonical bytes.
pub trait OcsfSigner: Send + Sync {
    /// Sign `canonical_bytes`, or `None` for an unsigned record.
    fn sign(&self, canonical_bytes: &[u8]) -> Option<Signed>;
}

/// No-op: hash-chained but unsigned. Default for demo / unprovisioned.
pub struct NoopSigner;

impl OcsfSigner for NoopSigner {
    fn sign(&self, _canonical_bytes: &[u8]) -> Option<Signed> {
        None
    }
}

/// DSSE signer: ECDSA-P256-SHA256 over the PAE of the event's canonical
/// bytes, deterministic per RFC 6979.
///
/// The key is operator-provided (config: `signing_key_pem` inline or
/// `signing_key_pem_path`); this crate holds a key handle, not a key
/// service. Custody (HSM/KMS residency, rotation epochs, JWKS publication
/// and its never-unpublish guarantee) is deliberately not plugin scope;
/// it belongs to whoever operates the signing authority named by
/// `attestation.authority_uid`.
pub struct DsseSigner {
    key: SigningKey,
    key_id: Option<String>,
}

impl DsseSigner {
    /// Build from a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). SEC1
    /// (`BEGIN EC PRIVATE KEY`) is deliberately not parsed: convert once
    /// with `openssl pkcs8 -topk8 -nocrypt` rather than making the plugin
    /// guess at formats.
    ///
    /// # Errors
    ///
    /// When `pem` is not a PKCS#8 P-256 private key. The message names the
    /// expected format and the conversion command.
    pub fn from_pem(pem: &str, key_id: Option<String>) -> Result<Self, String> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| {
            format!(
                "signing=dsse requires a PKCS#8 P-256 private key PEM \
                 (-----BEGIN PRIVATE KEY-----); parse failed: {e}. \
                 A SEC1 'BEGIN EC PRIVATE KEY' file converts with: \
                 openssl pkcs8 -topk8 -nocrypt -in key.pem"
            )
        })?;
        Ok(Self { key, key_id })
    }

    /// The corresponding public key: what an operator publishes (JWKS)
    /// and a verifier fetches. Exposed for tests, the examples, and
    /// downstream verification tooling.
    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        *self.key.verifying_key()
    }
}

impl OcsfSigner for DsseSigner {
    fn sign(&self, canonical_bytes: &[u8]) -> Option<Signed> {
        let sig: p256::ecdsa::Signature = self.key.sign(&dsse_pae(canonical_bytes));
        Some(Signed {
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
            key_id: self.key_id.clone(),
            // Descriptor only. `algorithm` / `serialization` carry the
            // normalized schema captions; curve and hash resolve via the
            // JWKS kid.
            digital_signature: json!({
                "algorithm_id": 3,
                "algorithm": "ECDSA",
                "serialization_id": 5,
                "serialization": "DSSE",
            }),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use serde_json::json;

    #[test]
    fn canonical_form_is_sorted_and_compact() {
        // Build with unsorted key insertion; canonical output must be
        // key-sorted, compact, and nest-stable.
        let v = json!({
            "z": [3, 1, 2],                    // array order preserved
            "a": { "y": "b", "x": true },      // nested keys sorted
            "m": null,
        });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v)).unwrap(),
            r#"{"a":{"x":true,"y":"b"},"m":null,"z":[3,1,2]}"#
        );
    }

    /// The emitted `fingerprint.serialization_id = 2` (JCS) is a promise
    /// that a verifier can reproduce these bytes with an off-the-shelf
    /// RFC 8785 implementation. Integers, ASCII keys: the common case.
    #[test]
    fn canonical_form_matches_jcs_for_integers_and_ascii_keys() {
        let v = json!({
            "b": 10,
            "a": -1,
            "A": 0,          // uppercase sorts before lowercase in both orders
            "nested": { "z": [1, 2], "y": "s" },
        });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v)).unwrap(),
            r#"{"A":0,"a":-1,"b":10,"nested":{"y":"s","z":[1,2]}}"#
        );
    }

    /// RFC 8785 section 3.2.2.3: floats print in ES6 `Number::toString`
    /// form. A float bound in a tool's `inputSchema` is routine MCP
    /// metadata, and `serde_json`'s own `2.0` / `1e21` would not verify.
    #[test]
    fn floats_canonicalize_in_es6_form() {
        let v = json!({ "minimum": 0.0, "maximum": 2.0, "default": 1.0 });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v)).unwrap(),
            r#"{"default":1,"maximum":2,"minimum":0}"#
        );
        assert_eq!(canonical_bytes(&json!({ "x": 1e21 })), br#"{"x":1e+21}"#);

        // Integers keep their exact digits, including past 2^53.
        assert_eq!(
            canonical_bytes(&json!([1_755_648_000_000_000_000_u64, -7, 0])),
            b"[1755648000000000000,-7,0]"
        );
    }

    /// RFC 8785 Appendix B number vectors, by IEEE 754 bit pattern, plus
    /// the placement-rule edges (21 digits, `1e-7`, signed zero).
    #[test]
    fn es6_number_form_matches_rfc_8785_appendix_b() {
        let cases: &[(u64, &str)] = &[
            (0x0000_0000_0000_0000, "0"),
            (0x8000_0000_0000_0000, "0"),
            (0x0000_0000_0000_0001, "5e-324"),
            (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
            (0x4340_0000_0000_0000, "9007199254740992"),
            (0x4340_0000_0000_0001, "9007199254740994"),
            (0x444b_1ae4_d6e2_ef50, "1e+21"),
            (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
            (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
            (0x41b3_de43_5555_5553, "333333333.3333332"),
            (0x41b3_de43_5555_5554, "333333333.33333325"),
            (0x41b3_de43_5555_5555, "333333333.3333333"),
            (0x41b3_de43_5555_5556, "333333333.3333334"),
            (0x41b3_de43_5555_5557, "333333333.33333343"),
            (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
            (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
        ];
        for (bits, expected) in cases {
            let mut out = Vec::new();
            write_es6_number(f64::from_bits(*bits), &mut out);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                *expected,
                "bits {bits:#018x}"
            );
        }
        let edges: &[(f64, &str)] = &[
            (1e20, "100000000000000000000"),
            (1e-7, "1e-7"),
            (4.5, "4.5"),
            (-1.5, "-1.5"),
            (1.5e-10, "1.5e-10"),
            (123.456, "123.456"),
            (100.0, "100"),
            (2_f64.powi(63), "9223372036854776000"),
        ];
        for (f, expected) in edges {
            let mut out = Vec::new();
            write_es6_number(*f, &mut out);
            assert_eq!(String::from_utf8(out).unwrap(), *expected, "value {f:?}");
        }
    }

    /// RFC 8785 section 3.2.3 worked example: keys sort by UTF-16 code
    /// units, so the smiley (a surrogate pair, `D83D DE02`) precedes the
    /// Hebrew letter (`FB33`); byte or code point order would put it last.
    /// `U+0080` stays an unescaped raw character.
    #[test]
    fn keys_sort_by_utf16_code_units() {
        let v = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f602}": "Smiley",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis",
        });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v)).unwrap(),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
             \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
             \"\u{1f602}\":\"Smiley\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
        // é (00E9), 😀 (D83D DE00), ﬀ (FB00) in UTF-16 order; byte order
        // would give é, ﬀ, 😀.
        assert_eq!(
            canonical_bytes(&json!({ "ﬀ": 1, "😀": 2, "é": 3 })),
            "{\"é\":3,\"😀\":2,\"ﬀ\":1}".as_bytes()
        );
    }

    /// `canonical_order` is a re-keying, not a re-shaping: the rebuilt
    /// value equals the original (map equality ignores order) and its
    /// compact form is the canonical bytes when the map keeps insertion
    /// order, or byte order otherwise, which agree for ASCII keys.
    #[test]
    fn canonical_order_preserves_content() {
        let v = json!({
            "z": [{ "b": 1, "a": 2 }, 3],
            "a": { "y": "b", "x": true },
        });
        let ordered = canonical_order(&v);
        assert_eq!(ordered, v);
        assert_eq!(
            serde_json::to_vec(&ordered).unwrap(),
            canonical_bytes(&v),
            "ASCII keys: compact print of the re-keyed value is the canonical form"
        );
    }

    #[test]
    fn fingerprint_is_reproducible_from_canonical_bytes() {
        let v = json!({ "b": 1, "a": ["PII", "secret"] });
        let h1 = fingerprint_value(&canonical_bytes(&v));
        let h2 = fingerprint_value(&canonical_bytes(&v.clone()));
        assert_eq!(h1, h2);
        // Bare lowercase hex: algorithm/encoding are declared by the
        // sibling fingerprint fields, not smuggled into `value`.
        assert_eq!(h1.len(), 64);
        assert!(
            h1.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    #[test]
    fn dsse_pae_matches_the_spec_form() {
        // PAE("application/vnd.ocsf.event+json", "hello"):
        // the payload type is 31 bytes, the payload 5.
        assert_eq!(
            dsse_pae(b"hello"),
            b"DSSEv1 31 application/vnd.ocsf.event+json 5 hello".to_vec()
        );
    }

    fn test_key() -> SigningKey {
        // Fixed scalar (well below the P-256 group order) so signature
        // output is deterministic across runs: RFC 6979 makes ECDSA
        // deterministic per (key, message). Test/demo key only; never a
        // production pattern.
        SigningKey::from_slice(&[0x11_u8; 32]).expect("valid P-256 scalar")
    }

    #[test]
    fn dsse_signature_is_deterministic_and_verifies() {
        let pem = {
            use p256::pkcs8::EncodePrivateKey as _;
            test_key()
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string()
        };
        let signer = DsseSigner::from_pem(&pem, Some("test-key-1".into())).unwrap();

        let payload = canonical_bytes(&json!({ "class_uid": 6003, "activity_id": 99 }));
        let s1 = signer.sign(&payload).unwrap();
        let s2 = signer.sign(&payload).unwrap();
        // RFC 6979: same key + same message -> same signature.
        assert_eq!(s1.signature, s2.signature);
        assert_eq!(s1.key_id.as_deref(), Some("test-key-1"));
        assert_eq!(s1.digital_signature["algorithm_id"], 3);
        assert_eq!(s1.digital_signature["serialization_id"], 5);

        // Round-trip verify with nothing but the public key and the
        // documented PAE rule.
        let der = base64::engine::general_purpose::STANDARD
            .decode(&s1.signature)
            .unwrap();
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        signer
            .verifying_key()
            .verify(&dsse_pae(&payload), &sig)
            .expect("signature must verify over the PAE bytes");
    }

    #[test]
    fn from_pem_rejects_garbage_loudly() {
        let err = match DsseSigner::from_pem("not a pem", None) {
            Ok(_) => panic!("garbage PEM must not parse"),
            Err(e) => e,
        };
        assert!(
            err.contains("PKCS#8"),
            "error must name the expected format: {err}"
        );
    }
}
