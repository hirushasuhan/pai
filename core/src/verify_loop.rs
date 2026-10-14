//! Verify-Loop Frame, HMAC-SHA256 Authentication, Tagged Value Codec,
//! and Canonical Example Extraction (Phase 2 Slice 2 / ADR-011)
//!
//! Provides a pure safe (`#![forbid(unsafe_code)]`), deterministic Rust port of:
//! - `get_codec_policy`, `encode_value`, `decode_value`, `decode_envelope_json` (`research/value_codec.py`)
//! - `format_authenticated_verdict_frame`, `verify_verdict_frame` (`research/verify_loop.py`)
//! - `extract_example_assertions` (`research/verify_loop.py`)
//!
//! Security & Reliability Invariants:
//! 1. `#![forbid(unsafe_code)]` and zero unchecked byte-slice indexing on strings.
//! 2. Constant-time HMAC-SHA256 verification (`constant_time_eq`).
//! 3. Strict resource bounds on all untrusted inputs:
//!    - Stream size <= 1 MiB (`MAX_VERDICT_STREAM_BYTES`), frame payload <= 256 KiB (`MAX_VERDICT_FRAME_BYTES`),
//!      encoded envelope JSON <= 1 MiB (`MAX_ENCODED_JSON_BYTES`).
//!    - Recursion depth <= 32 (`MAX_RECURSION_DEPTH`).
//!    - Collection length <= 1,000 (`MAX_COLLECTION_LENGTH`).
//!    - Total item/node count <= 50,000 (`MAX_ITEM_COUNT`).
//!    - Signed 64-bit integer bounds (`[i64::MIN, i64::MAX]`).
//!    - Strict 2-key codec envelope (`{"t", "v"}`), duplicate dict/set/frozenset/JSON-object keys rejected.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_RECURSION_DEPTH: usize = 32;
pub const MAX_COLLECTION_LENGTH: usize = 1_000;
pub const MAX_ITEM_COUNT: usize = 50_000;
pub const MAX_ENCODED_JSON_BYTES: usize = 1_048_576;
pub const MAX_VERDICT_STREAM_BYTES: usize = 1_048_576;
pub const MAX_VERDICT_FRAME_BYTES: usize = 262_144;
pub const MAX_VERDICT_COUNT_VALUE: i64 = 1_000_000;
pub const MAX_EXTRACTED_STATEMENTS: usize = 50;
pub const MIN_INT64: i64 = i64::MIN;
pub const MAX_INT64: i64 = i64::MAX;


const MAX_RAW_JSON_DEPTH: usize = 128;
const MAX_RAW_JSON_NODES: usize = 200_000;

pub const VERDICT_START_MARKER: &str = "---PAI_VERDICT_START---";
pub const VERDICT_END_MARKER: &str = "---PAI_VERDICT_END---";

// ============================================================================
// 1. Codec Policy & Errors
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecPolicy {
    pub max_recursion_depth: usize,
    pub max_collection_length: usize,
    pub max_item_count: usize,
    pub min_int64: i64,
    pub max_int64: i64,
    pub strict_envelope_keys: Vec<String>,
    pub reject_duplicate_dict_keys: bool,
    pub reject_duplicate_set_elements: bool,
    pub reject_bool_for_int_or_float: bool,
}

pub fn get_codec_policy() -> CodecPolicy {
    CodecPolicy {
        max_recursion_depth: MAX_RECURSION_DEPTH,
        max_collection_length: MAX_COLLECTION_LENGTH,
        max_item_count: MAX_ITEM_COUNT,
        min_int64: MIN_INT64,
        max_int64: MAX_INT64,
        strict_envelope_keys: vec!["t".to_string(), "v".to_string()],
        reject_duplicate_dict_keys: true,
        reject_duplicate_set_elements: true,
        reject_bool_for_int_or_float: true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError {
    pub message: String,
}

impl CodecError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CodecError {}

// ============================================================================
// 2. Pure-Rust SHA-256, HMAC-SHA256 & Constant-Time Digest Comparison
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, slot) in w.iter_mut().take(16).enumerate() {
        let base = i * 4;
        if let (Some(&b0), Some(&b1), Some(&b2), Some(&b3)) = (
            block.get(base),
            block.get(base + 1),
            block.get(base + 2),
            block.get(base + 3),
        ) {
            *slot = u32::from_be_bytes([b0, b1, b2, b3]);
        }
    }
    for i in 16..64 {
        let w_i_15 = w.get(i - 15).copied().unwrap_or(0);
        let w_i_2 = w.get(i - 2).copied().unwrap_or(0);
        let w_i_16 = w.get(i - 16).copied().unwrap_or(0);
        let w_i_7 = w.get(i - 7).copied().unwrap_or(0);
        let s0 = w_i_15.rotate_right(7) ^ w_i_15.rotate_right(18) ^ (w_i_15 >> 3);
        let s1 = w_i_2.rotate_right(17) ^ w_i_2.rotate_right(19) ^ (w_i_2 >> 10);
        if let Some(slot) = w.get_mut(i) {
            *slot = w_i_16
                .wrapping_add(s0)
                .wrapping_add(w_i_7)
                .wrapping_add(s1);
        }
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let ki = SHA256_K.get(i).copied().unwrap_or(0);
        let wi = w.get(i).copied().unwrap_or(0);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(ki)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Streaming FIPS 180-4 SHA-256 hasher for chunked hashing.
#[derive(Clone, Debug)]
pub struct Sha256Hasher {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut idx = (self.count as usize) & 0x3f;
        self.count = self.count.wrapping_add(data.len() as u64);
        let mut pos = 0;
        if idx > 0 && idx + data.len() >= 64 {
            let needed = 64 - idx;
            self.buffer[idx..64].copy_from_slice(&data[..needed]);
            sha256_compress(&mut self.state, &self.buffer);
            pos += needed;
            idx = 0;
        }
        while pos + 64 <= data.len() {
            let chunk: &[u8; 64] = data[pos..pos + 64].try_into().unwrap();
            sha256_compress(&mut self.state, chunk);
            pos += 64;
        }
        if pos < data.len() {
            let rem = &data[pos..];
            self.buffer[idx..idx + rem.len()].copy_from_slice(rem);
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.count.wrapping_mul(8);
        let idx = (self.count as usize) & 0x3f;
        self.buffer[idx] = 0x80;
        if idx < 56 {
            for b in &mut self.buffer[idx + 1..56] {
                *b = 0;
            }
        } else {
            for b in &mut self.buffer[idx + 1..64] {
                *b = 0;
            }
            sha256_compress(&mut self.state, &self.buffer);
            self.buffer = [0u8; 64];
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        sha256_compress(&mut self.state, &self.buffer);
        let mut out = [0u8; 32];
        for (i, val) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the FIPS 180-4 SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256Hasher::new();
    h.update(data);
    h.finalize()
}

/// Computes the RFC 2104 HMAC-SHA256 authentication tag over `message` using `key`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else if let Some(slot) = key_block.get_mut(..key.len()) {
        slot.copy_from_slice(key);
    }

    let mut o_key_pad = [0u8; 64];
    let mut i_key_pad = [0u8; 64];
    for i in 0..64 {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&i_key_pad);
    inner_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_input);

    let mut outer_input = [0u8; 96];
    outer_input[..64].copy_from_slice(&o_key_pad);
    outer_input[64..96].copy_from_slice(&inner_hash);
    sha256(&outer_input)
}

/// Encodes a byte slice as lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Compares two byte slices in constant time (when lengths match) to prevent timing side-channels.
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Formats a float identically to Python's `repr(float)` and `json.dumps(float)`:
/// - Shortest round-trip digits (via Dragonbox/Ryu scientific form)
/// - Scientific exponent form (`e+XX` / `e-XX` with >=2 exponent digits) when exponent < -4 or >= 16
/// - Positional form with at least one digit after the point (`.0`) when -4 <= exponent < 16
pub fn format_python_float(f: f64) -> String {
    if !f.is_finite() {
        if f.is_nan() {
            return "nan".to_string();
        } else if f > 0.0 {
            return "inf".to_string();
        } else {
            return "-inf".to_string();
        }
    }
    let is_negative = f.is_sign_negative();
    let abs_f = f.abs();
    if abs_f == 0.0 {
        return if is_negative {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }

    let s = format!("{:e}", abs_f);
    let Some((mantissa, raw_exp)) = s.split_once('e') else {
        return s;
    };
    let exp: i32 = raw_exp.parse().unwrap_or(0);

    let mut out = String::new();
    if is_negative {
        out.push('-');
    }

    if !(-4..16).contains(&exp) {
        out.push_str(mantissa);
        if exp >= 0 {
            out.push_str(&format!("e+{:02}", exp));
        } else {
            out.push_str(&format!("e-{:02}", -exp));
        }
    } else if exp >= 0 {
        let digits: Vec<char> = mantissa.chars().filter(|c| *c != '.').collect();
        let num_before = (exp + 1) as usize;
        if digits.len() <= num_before {
            for c in &digits {
                out.push(*c);
            }
            for _ in 0..(num_before - digits.len()) {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            for c in &digits[..num_before] {
                out.push(*c);
            }
            out.push('.');
            for c in &digits[num_before..] {
                out.push(*c);
            }
        }
    } else {
        out.push_str("0.");
        let leading_zeros = (-exp - 1) as usize;
        for _ in 0..leading_zeros {
            out.push('0');
        }
        for c in mantissa.chars().filter(|c| *c != '.') {
            out.push(c);
        }
    }

    out
}

// ============================================================================
// 3. Strict Bounded RFC 8259 JSON Value & Parser
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum StrictJson {
    Null,
    Bool(bool),
    Int(i64),
    OutOfRangeInt,
    Float(f64),
    Str(String),
    Array(Vec<StrictJson>),
    Object(BTreeMap<String, StrictJson>),
}

impl StrictJson {
    /// Converts a `serde_json::Value` (with `arbitrary_precision` enabled) into `StrictJson`,
    /// preserving the exact distinction between integer tokens and float tokens, and flagging
    /// integers outside `[i64::MIN, i64::MAX]` as `StrictJson::OutOfRangeInt`.
    pub fn from_serde_value(val: &serde_json::Value) -> Self {
        match val {
            serde_json::Value::Null => StrictJson::Null,
            serde_json::Value::Bool(b) => StrictJson::Bool(*b),
            serde_json::Value::Number(n) => {
                let raw = n.to_string();
                if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                    match raw.parse::<f64>() {
                        Ok(f) => StrictJson::Float(f),
                        Err(_) => StrictJson::Float(f64::INFINITY),
                    }
                } else {
                    match raw.parse::<i64>() {
                        Ok(i) => StrictJson::Int(i),
                        Err(_) => StrictJson::OutOfRangeInt,
                    }
                }
            }
            serde_json::Value::String(s) => StrictJson::Str(s.clone()),
            serde_json::Value::Array(arr) => {
                StrictJson::Array(arr.iter().map(StrictJson::from_serde_value).collect())
            }
            serde_json::Value::Object(map) => {
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    out.insert(k.clone(), StrictJson::from_serde_value(v));
                }
                StrictJson::Object(out)
            }
        }
    }

    pub fn to_serde_value(&self) -> Result<serde_json::Value, CodecError> {
        match self {
            StrictJson::Null => Ok(serde_json::Value::Null),
            StrictJson::Bool(b) => Ok(serde_json::Value::Bool(*b)),
            StrictJson::Int(i) => Ok(serde_json::Value::Number(serde_json::Number::from(*i))),
            StrictJson::OutOfRangeInt => Err(CodecError::new("Out-of-range i64 integer")),
            StrictJson::Float(f) => {
                if !f.is_finite() {
                    return Err(CodecError::new("Non-finite float cannot be raw JSON number"));
                }
                let s = format_python_float(*f);
                let num: serde_json::Number = serde_json::from_str(&s)
                    .map_err(|_| CodecError::new("Failed to parse canonical float as JSON number"))?;
                Ok(serde_json::Value::Number(num))
            }
            StrictJson::Str(s) => Ok(serde_json::Value::String(s.clone())),
            StrictJson::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(item.to_serde_value()?);
                }
                Ok(serde_json::Value::Array(out))
            }
            StrictJson::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    out.insert(k.clone(), v.to_serde_value()?);
                }
                Ok(serde_json::Value::Object(out))
            }
        }
    }

    /// Formats `StrictJson` identically to Python's `json.dumps(obj, sort_keys=True)`:
    /// - `ensure_ascii=True`
    /// - `item_separator=", "` and `key_separator=": "`
    /// - keys sorted in Unicode code point order (`BTreeMap`)
    pub fn to_python_canonical_json(&self) -> String {
        let mut buf = String::new();
        self.write_python_canonical_json(&mut buf);
        buf
    }

    fn write_python_canonical_json(&self, out: &mut String) {
        match self {
            StrictJson::Null => out.push_str("null"),
            StrictJson::Bool(true) => out.push_str("true"),
            StrictJson::Bool(false) => out.push_str("false"),
            StrictJson::Int(n) => out.push_str(&n.to_string()),
            StrictJson::OutOfRangeInt => out.push_str("null"),
            StrictJson::Float(f) => {
                out.push_str(&format_python_float(*f));
            }
            StrictJson::Str(s) => write_python_json_string(s, out),
            StrictJson::Array(items) => {
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push_str(", ");
                    }
                    item.write_python_canonical_json(out);
                }
                out.push(']');
            }
            StrictJson::Object(map) => {
                out.push('{');
                for (idx, (k, v)) in map.iter().enumerate() {
                    if idx > 0 {
                        out.push_str(", ");
                    }
                    write_python_json_string(k, out);
                    out.push_str(": ");
                    v.write_python_canonical_json(out);
                }
                out.push('}');
            }
        }
    }
}


fn write_python_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) <= 0x7e => {
                out.push(c);
            }
            c if (c as u32) <= 0xffff => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => {
                let u = (c as u32) - 0x10000;
                let high = 0xd800 | ((u >> 10) & 0x3ff);
                let low = 0xdc00 | (u & 0x3ff);
                out.push_str(&format!("\\u{:04x}\\u{:04x}", high, low));
            }
        }
    }
    out.push('"');
}

struct StrictJsonParser<'a> {
    bytes: &'a [u8],
    raw_str: &'a str,
    pos: usize,
    max_depth: usize,
    max_nodes: usize,
    max_collection_len: Option<usize>,
    allow_floats: bool,
    nodes: usize,
}

impl<'a> StrictJsonParser<'a> {
    fn new(
        raw_str: &'a str,
        max_depth: usize,
        max_nodes: usize,
        max_collection_len: Option<usize>,
        allow_floats: bool,
    ) -> Self {
        Self {
            bytes: raw_str.as_bytes(),
            raw_str,
            pos: 0,
            max_depth,
            max_nodes,
            max_collection_len,
            allow_floats,
            nodes: 0,
        }
    }

    fn bump_node(&mut self) -> Result<(), String> {
        self.nodes += 1;
        if self.nodes > self.max_nodes {
            return Err(format!("JSON node count limit exceeded: {}", self.max_nodes));
        }
        Ok(())
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_root(&mut self) -> Result<StrictJson, String> {
        self.skip_ws();
        let val = self.parse_value(0)?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err("Trailing characters after JSON value".to_string());
        }
        Ok(val)
    }

    fn parse_value(&mut self, depth: usize) -> Result<StrictJson, String> {
        if depth > self.max_depth {
            return Err(format!("JSON nesting depth limit exceeded: {}", self.max_depth));
        }
        self.bump_node()?;
        self.skip_ws();
        let b = self.peek().ok_or_else(|| "Unexpected EOF in JSON".to_string())?;
        match b {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => self.parse_string().map(StrictJson::Str),
            b't' => {
                if self.bytes.get(self.pos..self.pos + 4) == Some(b"true") {
                    self.pos += 4;
                    Ok(StrictJson::Bool(true))
                } else {
                    Err("Invalid token starting with 't'".to_string())
                }
            }
            b'f' => {
                if self.bytes.get(self.pos..self.pos + 5) == Some(b"false") {
                    self.pos += 5;
                    Ok(StrictJson::Bool(false))
                } else {
                    Err("Invalid token starting with 'f'".to_string())
                }
            }
            b'n' => {
                if self.bytes.get(self.pos..self.pos + 4) == Some(b"null") {
                    self.pos += 4;
                    Ok(StrictJson::Null)
                } else {
                    Err("Invalid token starting with 'n'".to_string())
                }
            }
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(format!("Unexpected byte in JSON: 0x{:02x}", b)),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<StrictJson, String> {
        self.pos += 1; // consume '{'
        self.skip_ws();
        let mut map = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(StrictJson::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err("Expected string key in JSON object".to_string());
            }
            self.bump_node()?;
            let key = self.parse_string()?;
            if map.contains_key(&key) {
                return Err(format!("Duplicate key in JSON object: {:?}", key));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err("Expected ':' after key in JSON object".to_string());
            }
            self.pos += 1;
            let val = self.parse_value(depth + 1)?;
            map.insert(key, val);
            if let Some(limit) = self.max_collection_len {
                if map.len() > limit {
                    return Err(format!("JSON object length exceeds limit {}", limit));
                }
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(StrictJson::Object(map));
                }
                _ => return Err("Expected ',' or '}' in JSON object".to_string()),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<StrictJson, String> {
        self.pos += 1; // consume '['
        self.skip_ws();
        let mut arr = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(StrictJson::Array(arr));
        }
        loop {
            let val = self.parse_value(depth + 1)?;
            arr.push(val);
            if let Some(limit) = self.max_collection_len {
                if arr.len() > limit {
                    return Err(format!("JSON array length exceeds limit {}", limit));
                }
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(StrictJson::Array(arr));
                }
                _ => return Err("Expected ',' or ']' in JSON array".to_string()),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        let slice = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| "Unexpected EOF in \\uXXXX escape".to_string())?;
        let mut val: u16 = 0;
        for &b in slice {
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => return Err("Invalid hex digit in \\uXXXX escape".to_string()),
            };
            val = (val << 4) | digit;
        }
        self.pos += 4;
        Ok(val)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.pos += 1; // consume opening '"'
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes.get(self.pos).copied().unwrap_or(0);
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self
                    .bytes
                    .get(self.pos)
                    .copied()
                    .ok_or_else(|| "Unexpected EOF after '\\' in string".to_string())?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xd800..=0xdbff).contains(&code) {
                            // High surrogate: must be followed by \uDC00..=\uDFFF
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err("Lone high surrogate in JSON string".to_string());
                            }
                            self.pos += 2;
                            let low = self.parse_hex4()?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err("Invalid low surrogate in JSON string".to_string());
                            }
                            let combined =
                                0x10000 + (((code - 0xd800) as u32) << 10) + ((low - 0xdc00) as u32);
                            let ch = char::from_u32(combined)
                                .ok_or_else(|| "Invalid surrogate codepoint".to_string())?;
                            out.push(ch);
                        } else if (0xdc00..=0xdfff).contains(&code) {
                            return Err("Lone low surrogate in JSON string".to_string());
                        } else {
                            let ch = char::from_u32(code as u32)
                                .ok_or_else(|| "Invalid Unicode escape".to_string())?;
                            out.push(ch);
                        }
                    }
                    _ => return Err(format!("Invalid string escape: \\{}", esc as char)),
                }
            } else if b < 0x20 {
                return Err(format!("Unescaped control character in JSON string: 0x{:02x}", b));
            } else {
                // Advance by one full UTF-8 char from self.raw_str at self.pos
                let tail = self
                    .raw_str
                    .get(self.pos..)
                    .ok_or_else(|| "Invalid UTF-8 boundary in JSON string".to_string())?;
                let ch = tail
                    .chars()
                    .next()
                    .ok_or_else(|| "Unexpected EOF in JSON string".to_string())?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err("Unterminated JSON string".to_string())
    }

    fn parse_number(&mut self) -> Result<StrictJson, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err("Leading zeros are not permitted in JSON numbers".to_string());
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err("Expected digit in JSON number".to_string()),
        }

        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("Expected digit after decimal point in JSON number".to_string());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("Expected digit in JSON number exponent".to_string());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        let num_str = self
            .raw_str
            .get(start..self.pos)
            .ok_or_else(|| "Invalid number slice".to_string())?;

        if is_float {
            if !self.allow_floats {
                return Err(format!("Float literal not permitted: {}", num_str));
            }
            let fval = num_str
                .parse::<f64>()
                .map_err(|e| format!("Invalid JSON float {}: {}", num_str, e))?;
            if !fval.is_finite() {
                return Err(format!("JSON float overflowed to non-finite value: {}", num_str));
            }
            Ok(StrictJson::Float(fval))
        } else {
            if num_str.len() > 32 {
                return Err("JSON integer exceeds maximum digit length".to_string());
            }
            let ival = num_str
                .parse::<i64>()
                .map_err(|_| format!("JSON integer out of signed 64-bit range: {}", num_str))?;
            Ok(StrictJson::Int(ival))
        }
    }
}

pub fn parse_strict_json(
    raw_json: &str,
    max_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_collection_len: Option<usize>,
    allow_floats: bool,
) -> Result<StrictJson, String> {
    if raw_json.len() > max_bytes {
        return Err(format!(
            "JSON input exceeds maximum byte size ({} > {})",
            raw_json.len(),
            max_bytes
        ));
    }
    let mut parser = StrictJsonParser::new(
        raw_json,
        max_depth,
        max_nodes,
        max_collection_len,
        allow_floats,
    );
    parser.parse_root()
}

// ============================================================================
// 4. Tagged Value Codec (`PaiValue`, `encode_value`, `decode_value`)
// ============================================================================

#[derive(Debug, Clone)]
pub enum PaiValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    None,
    Bytes(Vec<u8>),
    List(Vec<PaiValue>),
    Tuple(Vec<PaiValue>),
    Set(Vec<PaiValue>),
    FrozenSet(Vec<PaiValue>),
    Dict(Vec<(PaiValue, PaiValue)>),
}

impl PaiValue {
    pub fn python_type_name(&self) -> &'static str {
        match self {
            PaiValue::Bool(_) => "bool",
            PaiValue::Int(_) => "int",
            PaiValue::Float(_) => "float",
            PaiValue::Str(_) => "str",
            PaiValue::None => "NoneType",
            PaiValue::Bytes(_) => "bytes",
            PaiValue::List(_) => "list",
            PaiValue::Tuple(_) => "tuple",
            PaiValue::Set(_) => "set",
            PaiValue::FrozenSet(_) => "frozenset",
            PaiValue::Dict(_) => "dict",
        }
    }

    pub fn is_hashable(&self) -> bool {
        match self {
            PaiValue::Bool(_)
            | PaiValue::Int(_)
            | PaiValue::Float(_)
            | PaiValue::Str(_)
            | PaiValue::None
            | PaiValue::Bytes(_) => true,
            PaiValue::Tuple(elts) | PaiValue::FrozenSet(elts) => {
                elts.iter().all(PaiValue::is_hashable)
            }
            PaiValue::List(_) | PaiValue::Set(_) | PaiValue::Dict(_) => false,
        }
    }
}

fn int_equals_float(i: i64, f: f64) -> bool {
    if !f.is_finite() || f.fract() != 0.0 {
        return false;
    }
    // Note: i64::MIN as f64 is -9223372036854775808.0 (exact power of 2),
    // while i64::MAX as f64 rounds up to 9223372036854775808.0 (2^63).
    if !(-9223372036854775808.0..9223372036854775808.0).contains(&f) {
        return false;
    }
    (f as i128) == (i as i128)
}

/// Emulates Python's `a == b` key equality for hashable values in `set`, `frozenset`, and `dict`.
/// In Python: `True == 1 == 1.0`, `False == 0 == 0.0 == -0.0`, and tuples/frozensets compare
/// recursively using this equality. Two decoded `float("nan")` instances are distinct objects
/// with `nan != nan`.
pub fn python_key_eq(a: &PaiValue, b: &PaiValue) -> bool {
    match (a, b) {
        (PaiValue::Bool(x), PaiValue::Bool(y)) => x == y,
        (PaiValue::Int(x), PaiValue::Int(y)) => x == y,
        (PaiValue::Float(x), PaiValue::Float(y)) => {
            if x.is_nan() || y.is_nan() {
                false
            } else {
                x == y
            }
        }
        (PaiValue::Bool(b_val), PaiValue::Int(i_val))
        | (PaiValue::Int(i_val), PaiValue::Bool(b_val)) => (*b_val as i64) == *i_val,
        (PaiValue::Bool(b_val), PaiValue::Float(f_val))
        | (PaiValue::Float(f_val), PaiValue::Bool(b_val)) => {
            int_equals_float(*b_val as i64, *f_val)
        }
        (PaiValue::Int(i_val), PaiValue::Float(f_val))
        | (PaiValue::Float(f_val), PaiValue::Int(i_val)) => int_equals_float(*i_val, *f_val),
        (PaiValue::Str(x), PaiValue::Str(y)) => x == y,
        (PaiValue::Bytes(x), PaiValue::Bytes(y)) => x == y,
        (PaiValue::None, PaiValue::None) => true,
        (PaiValue::Tuple(x), PaiValue::Tuple(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y.iter())
                    .all(|(ex, ey)| python_key_eq(ex, ey))
        }
        (PaiValue::FrozenSet(x), PaiValue::FrozenSet(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|ex| y.iter().any(|ey| python_key_eq(ex, ey)))
        }
        _ => false,
    }
}

pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut offset = 0;
    while offset + 3 <= bytes.len() {
        let b0 = bytes.get(offset).copied().unwrap_or(0);
        let b1 = bytes.get(offset + 1).copied().unwrap_or(0);
        let b2 = bytes.get(offset + 2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        offset += 3;
    }
    let rem = bytes.get(offset..).unwrap_or(&[]);
    if rem.len() == 1 {
        let b0 = rem.first().copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let b0 = rem.first().copied().unwrap_or(0);
        let b1 = rem.get(1).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
        out.push('=');
    }
    out
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes a Base64 string matching Python's `base64.b64decode(val.encode("ascii"), validate=True)`.
pub fn base64_decode_strict(s: &str) -> Result<Vec<u8>, CodecError> {
    if !s.is_ascii() {
        return Err(CodecError::new("Base64 payload contains non-ASCII characters"));
    }
    let bytes = s.as_bytes();
    if (bytes.len() & 3) != 0 {
        return Err(CodecError::new("Base64 length is not a multiple of 4"));
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let num_quads = bytes.len() / 4;
    let mut out = Vec::with_capacity(num_quads * 3);
    for q_idx in 0..num_quads {
        let is_last = q_idx + 1 == num_quads;
        let base = q_idx * 4;
        let c0 = bytes.get(base).copied().unwrap_or(0);
        let c1 = bytes.get(base + 1).copied().unwrap_or(0);
        let c2 = bytes.get(base + 2).copied().unwrap_or(0);
        let c3 = bytes.get(base + 3).copied().unwrap_or(0);

        let v0 = b64_val(c0).ok_or_else(|| CodecError::new("Invalid base64 character"))?;
        let v1 = b64_val(c1).ok_or_else(|| CodecError::new("Invalid base64 character"))?;

        if c2 == b'=' {
            if !is_last || c3 != b'=' {
                return Err(CodecError::new("Invalid base64 padding"));
            }
            out.push((v0 << 2) | (v1 >> 4));
        } else if c3 == b'=' {
            if !is_last {
                return Err(CodecError::new("Invalid base64 padding in non-final quantum"));
            }
            let v2 = b64_val(c2).ok_or_else(|| CodecError::new("Invalid base64 character"))?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
        } else {
            let v2 = b64_val(c2).ok_or_else(|| CodecError::new("Invalid base64 character"))?;
            let v3 = b64_val(c3).ok_or_else(|| CodecError::new("Invalid base64 character"))?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
            out.push(((v2 & 0x03) << 6) | v3);
        }
    }
    Ok(out)
}

struct ItemCounter {
    count: usize,
    limit: usize,
}

impl ItemCounter {
    fn new(limit: usize) -> Self {
        Self { count: 0, limit }
    }

    fn increment(&mut self) -> Result<(), CodecError> {
        self.count += 1;
        if self.count > self.limit {
            return Err(CodecError::new(format!(
                "Codec item limit exceeded: {} items",
                self.limit
            )));
        }
        Ok(())
    }
}

/// Encodes a `PaiValue` into a `StrictJson` tagged envelope `{"t": tag, "v": payload}`.
pub fn encode_value_strict(val: &PaiValue) -> Result<StrictJson, CodecError> {
    let mut counter = ItemCounter::new(MAX_ITEM_COUNT);
    encode_value_inner(val, 0, &mut counter)
}

/// Encodes a `PaiValue` into a `serde_json::Value` tagged envelope `{"t": tag, "v": payload}`.
pub fn encode_value(val: &PaiValue) -> Result<serde_json::Value, CodecError> {
    let strict = encode_value_strict(val)?;
    strict.to_serde_value()
}

fn make_envelope_obj(tag: &str, v: StrictJson) -> StrictJson {
    let mut map = BTreeMap::new();
    map.insert("t".to_string(), StrictJson::Str(tag.to_string()));
    map.insert("v".to_string(), v);
    StrictJson::Object(map)
}

fn encode_value_inner(
    val: &PaiValue,
    depth: usize,
    counter: &mut ItemCounter,
) -> Result<StrictJson, CodecError> {
    counter.increment()?;
    if depth > MAX_RECURSION_DEPTH {
        return Err(CodecError::new(format!(
            "Codec recursion depth limit exceeded: {}",
            MAX_RECURSION_DEPTH
        )));
    }

    match val {
        PaiValue::Bool(b) => Ok(make_envelope_obj("bool", StrictJson::Bool(*b))),
        PaiValue::Int(i) => Ok(make_envelope_obj("int", StrictJson::Int(*i))),
        PaiValue::Float(f) => {
            if f.is_nan() {
                Ok(make_envelope_obj("float", StrictJson::Str("nan".to_string())))
            } else if f.is_infinite() {
                let s = if *f > 0.0 { "inf" } else { "-inf" };
                Ok(make_envelope_obj("float", StrictJson::Str(s.to_string())))
            } else {
                Ok(make_envelope_obj("float", StrictJson::Float(*f)))
            }
        }
        PaiValue::Str(s) => Ok(make_envelope_obj("str", StrictJson::Str(s.clone()))),
        PaiValue::None => Ok(make_envelope_obj("none", StrictJson::Null)),
        PaiValue::Bytes(b) => Ok(make_envelope_obj(
            "bytes",
            StrictJson::Str(base64_encode(b)),
        )),
        PaiValue::List(items) => {
            if items.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: collection length {} > {}",
                    items.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(items.len());
            for x in items {
                out.push(encode_value_inner(x, depth + 1, counter)?);
            }
            Ok(make_envelope_obj("list", StrictJson::Array(out)))
        }
        PaiValue::Tuple(items) => {
            if items.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: collection length {} > {}",
                    items.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(items.len());
            for x in items {
                out.push(encode_value_inner(x, depth + 1, counter)?);
            }
            Ok(make_envelope_obj("tuple", StrictJson::Array(out)))
        }
        PaiValue::Set(items) => {
            if items.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: collection length {} > {}",
                    items.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(items.len());
            for x in items {
                out.push(encode_value_inner(x, depth + 1, counter)?);
            }
            out.sort_by_key(|item| item.to_python_canonical_json());
            Ok(make_envelope_obj("set", StrictJson::Array(out)))
        }
        PaiValue::FrozenSet(items) => {
            if items.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: collection length {} > {}",
                    items.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(items.len());
            for x in items {
                out.push(encode_value_inner(x, depth + 1, counter)?);
            }
            out.sort_by_key(|item| item.to_python_canonical_json());
            Ok(make_envelope_obj("frozenset", StrictJson::Array(out)))
        }
        PaiValue::Dict(pairs) => {
            if pairs.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: collection length {} > {}",
                    pairs.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(pairs.len());
            for (k, v) in pairs {
                let enc_k = encode_value_inner(k, depth + 1, counter)?;
                let enc_v = encode_value_inner(v, depth + 1, counter)?;
                out.push(StrictJson::Array(vec![enc_k, enc_v]));
            }
            Ok(make_envelope_obj("dict", StrictJson::Array(out)))
        }
    }
}

/// Decodes a `serde_json::Value` tagged envelope into a `PaiValue`.
pub fn decode_value(envelope: &serde_json::Value) -> Result<PaiValue, CodecError> {
    let strict = StrictJson::from_serde_value(envelope);
    decode_value_strict(&strict)
}

/// Decodes a `StrictJson` tagged envelope into a `PaiValue`.
pub fn decode_value_strict(envelope: &StrictJson) -> Result<PaiValue, CodecError> {
    let mut counter = ItemCounter::new(MAX_ITEM_COUNT);
    decode_value_inner(envelope, 0, &mut counter)
}

/// Parses a raw JSON string with strict bounds (<= 1 MiB, no duplicate keys, no NaN/Infinity,
/// i64 integer bounds) and decodes the resulting tagged envelope into a `PaiValue`.
pub fn decode_envelope_json(raw_json: &str) -> Result<PaiValue, CodecError> {
    let strict = parse_strict_json(
        raw_json,
        MAX_ENCODED_JSON_BYTES,
        MAX_RAW_JSON_DEPTH,
        MAX_RAW_JSON_NODES,
        None,
        true,
    )
    .map_err(CodecError::new)?;
    decode_value_strict(&strict)
}

fn decode_value_inner(
    envelope: &StrictJson,
    depth: usize,
    counter: &mut ItemCounter,
) -> Result<PaiValue, CodecError> {
    counter.increment()?;
    if depth > MAX_RECURSION_DEPTH {
        return Err(CodecError::new(format!(
            "Codec recursion depth limit exceeded: {}",
            MAX_RECURSION_DEPTH
        )));
    }

    let map = match envelope {
        StrictJson::Object(m) if m.len() == 2 => m,
        _ => {
            return Err(CodecError::new(
                "Malformed envelope: must be a dict containing strictly 't' and 'v' keys",
            ))
        }
    };

    let tag_val = map.get("t").ok_or_else(|| {
        CodecError::new("Malformed envelope: must be a dict containing strictly 't' and 'v' keys")
    })?;
    let val = map.get("v").ok_or_else(|| {
        CodecError::new("Malformed envelope: must be a dict containing strictly 't' and 'v' keys")
    })?;

    let tag = match tag_val {
        StrictJson::Str(s) => s.as_str(),
        _ => return Err(CodecError::new("Unknown or non-string codec tag")),
    };

    match tag {
        "int" => match val {
            StrictJson::Int(i) => Ok(PaiValue::Int(*i)),
            StrictJson::OutOfRangeInt => Err(CodecError::new(
                "Integer out of signed 64-bit range [-9223372036854775808, 9223372036854775807]",
            )),
            _ => Err(CodecError::new("Invalid payload for tag 'int'")),
        },
        "bool" => match val {
            StrictJson::Bool(b) => Ok(PaiValue::Bool(*b)),
            _ => Err(CodecError::new("Invalid payload for tag 'bool'")),
        },
        "float" => match val {
            StrictJson::Str(s) => match s.as_str() {
                "nan" => Ok(PaiValue::Float(f64::NAN)),
                "inf" => Ok(PaiValue::Float(f64::INFINITY)),
                "-inf" => Ok(PaiValue::Float(f64::NEG_INFINITY)),
                _ => Err(CodecError::new(format!("Invalid float special string: {}", s))),
            },
            StrictJson::Int(i) => Ok(PaiValue::Float(*i as f64)),
            StrictJson::Float(f) => {
                if !f.is_finite() {
                    return Err(CodecError::new(
                        "Non-finite numeric float payload must use canonical string ('nan', 'inf', '-inf')",
                    ));
                }
                Ok(PaiValue::Float(*f))
            }
            _ => Err(CodecError::new("Invalid payload for tag 'float'")),
        },
        "str" => match val {
            StrictJson::Str(s) => Ok(PaiValue::Str(s.clone())),
            _ => Err(CodecError::new("Invalid payload for tag 'str'")),
        },
        "none" => match val {
            StrictJson::Null => Ok(PaiValue::None),
            _ => Err(CodecError::new("Invalid payload for tag 'none'")),
        },
        "bytes" => match val {
            StrictJson::Str(s) => {
                let decoded = base64_decode_strict(s)?;
                Ok(PaiValue::Bytes(decoded))
            }
            _ => Err(CodecError::new("Invalid payload for tag 'bytes'")),
        },
        "list" => {
            let arr = match val {
                StrictJson::Array(a) => a,
                _ => return Err(CodecError::new("Invalid payload for tag 'list'")),
            };
            if arr.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: list length {} > {}",
                    arr.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(decode_value_inner(item, depth + 1, counter)?);
            }
            Ok(PaiValue::List(out))
        }
        "tuple" => {
            let arr = match val {
                StrictJson::Array(a) => a,
                _ => return Err(CodecError::new("Invalid payload for tag 'tuple'")),
            };
            if arr.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: tuple length {} > {}",
                    arr.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(decode_value_inner(item, depth + 1, counter)?);
            }
            Ok(PaiValue::Tuple(out))
        }
        "set" => {
            let arr = match val {
                StrictJson::Array(a) => a,
                _ => return Err(CodecError::new("Invalid payload for tag 'set'")),
            };
            if arr.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: set length {} > {}",
                    arr.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut res_set: Vec<PaiValue> = Vec::with_capacity(arr.len());
            for item_env in arr {
                let item = decode_value_inner(item_env, depth + 1, counter)?;
                if !item.is_hashable() {
                    return Err(CodecError::new("Unhashable element in set"));
                }
                if res_set.iter().any(|existing| python_key_eq(existing, &item)) {
                    return Err(CodecError::new("Duplicate element in set envelope"));
                }
                res_set.push(item);
            }
            Ok(PaiValue::Set(res_set))
        }
        "frozenset" => {
            let arr = match val {
                StrictJson::Array(a) => a,
                _ => return Err(CodecError::new("Invalid payload for tag 'frozenset'")),
            };
            if arr.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: frozenset length {} > {}",
                    arr.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut res_set: Vec<PaiValue> = Vec::with_capacity(arr.len());
            for item_env in arr {
                let item = decode_value_inner(item_env, depth + 1, counter)?;
                if !item.is_hashable() {
                    return Err(CodecError::new("Unhashable element in frozenset"));
                }
                if res_set.iter().any(|existing| python_key_eq(existing, &item)) {
                    return Err(CodecError::new("Duplicate element in frozenset envelope"));
                }
                res_set.push(item);
            }
            Ok(PaiValue::FrozenSet(res_set))
        }
        "dict" => {
            let arr = match val {
                StrictJson::Array(a) => a,
                _ => return Err(CodecError::new("Invalid payload for tag 'dict'")),
            };
            if arr.len() > MAX_COLLECTION_LENGTH {
                return Err(CodecError::new(format!(
                    "Codec item limit exceeded: dict length {} > {}",
                    arr.len(),
                    MAX_COLLECTION_LENGTH
                )));
            }
            let mut res_pairs: Vec<(PaiValue, PaiValue)> = Vec::with_capacity(arr.len());
            for pair_env in arr {
                let pair_arr = match pair_env {
                    StrictJson::Array(p) if p.len() == 2 => p,
                    _ => return Err(CodecError::new("Invalid dict entry pair")),
                };
                let k_env = pair_arr
                    .first()
                    .ok_or_else(|| CodecError::new("Invalid dict entry pair"))?;
                let v_env = pair_arr
                    .get(1)
                    .ok_or_else(|| CodecError::new("Invalid dict entry pair"))?;
                let k = decode_value_inner(k_env, depth + 1, counter)?;
                let v = decode_value_inner(v_env, depth + 1, counter)?;
                if !k.is_hashable() {
                    return Err(CodecError::new("Unhashable key in dict"));
                }
                if res_pairs.iter().any(|(ek, _)| python_key_eq(ek, &k)) {
                    return Err(CodecError::new("Duplicate key in dict envelope"));
                }
                res_pairs.push((k, v));
            }
            Ok(PaiValue::Dict(res_pairs))
        }
        _ => Err(CodecError::new(format!("Unknown codec tag: {}", tag))),
    }
}

// ============================================================================
// 5. Verdict Frame Authentication & Verification (`verify_verdict_frame`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictVerificationResult {
    pub passed: bool,
    pub status: String,
    pub error_type: Option<String>,
    pub discovered: i64,
    pub executed: i64,
    pub failed: i64,
    pub errors: i64,
}

impl VerdictVerificationResult {
    fn fail_result(
        status: &str,
        error_type: Option<&str>,
        discovered: i64,
        executed: i64,
        failed: i64,
        errors: i64,
    ) -> Self {
        Self {
            passed: false,
            status: status.to_string(),
            error_type: error_type.map(|s| s.to_string()),
            discovered,
            executed,
            failed,
            errors,
        }
    }
}

/// Signs a verdict payload `StrictJson::Object` using HMAC-SHA256 over canonical sorted-keys JSON
/// and wraps it in `---PAI_VERDICT_START---` / `---PAI_VERDICT_END---`.
pub fn format_authenticated_verdict_frame(
    verdict_payload: &BTreeMap<String, StrictJson>,
    hmac_key: &str,
) -> String {
    let mut without_mac = BTreeMap::new();
    for (k, v) in verdict_payload {
        if k != "mac" {
            without_mac.insert(k.clone(), v.clone());
        }
    }
    let canonical_json = StrictJson::Object(without_mac.clone()).to_python_canonical_json();
    let mac_sig = hex_encode(&hmac_sha256(hmac_key.as_bytes(), canonical_json.as_bytes()));
    without_mac.insert("mac".to_string(), StrictJson::Str(mac_sig));
    let signed_json = StrictJson::Object(without_mac).to_python_canonical_json();
    format!(
        "\n{}\n{}\n{}\n",
        VERDICT_START_MARKER, signed_json, VERDICT_END_MARKER
    )
}

fn is_python_whitespace(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t'
            | '\n'
            | '\r'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\x1f'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_strip(s: &str) -> &str {
    s.trim_matches(is_python_whitespace)
}

fn extract_verdict_count(map: &BTreeMap<String, StrictJson>, key: &str) -> Result<i64, String> {
    match map.get(key) {
        None => Ok(0),
        Some(StrictJson::Int(v)) if (0..=MAX_VERDICT_COUNT_VALUE).contains(v) => Ok(*v),
        Some(_) => Err(format!("Invalid count field {}", key)),
    }
}

fn validate_verdict_fields(map: &BTreeMap<String, StrictJson>) -> Result<(), String> {
    for count_key in ["discovered", "executed", "passed", "failed", "errors"] {
        let _ = extract_verdict_count(map, count_key)?;
    }
    if let Some(status_v) = map.get("status") {
        if !matches!(status_v, StrictJson::Str(_)) {
            return Err("Verdict 'status' field must be a string".to_string());
        }
    }
    if let Some(mac_v) = map.get("mac") {
        if !matches!(mac_v, StrictJson::Str(_)) {
            return Err("Verdict 'mac' field must be a string".to_string());
        }
    }
    if let Some(nonce_v) = map.get("session_nonce") {
        if !matches!(nonce_v, StrictJson::Str(_) | StrictJson::Null) {
            return Err("Verdict 'session_nonce' field must be a string or null".to_string());
        }
    }
    if let Some(hash_v) = map.get("test_hash") {
        if !matches!(hash_v, StrictJson::Str(_) | StrictJson::Null) {
            return Err("Verdict 'test_hash' field must be a string or null".to_string());
        }
    }
    if let Some(ids_v) = map.get("executed_test_ids") {
        match ids_v {
            StrictJson::Array(arr) => {
                if arr.iter().any(|x| !matches!(x, StrictJson::Str(_))) {
                    return Err("Verdict 'executed_test_ids' elements must be strings".to_string());
                }
            }
            _ => return Err("Verdict 'executed_test_ids' must be an array".to_string()),
        }
    }
    if let Some(failures_v) = map.get("failures") {
        match failures_v {
            StrictJson::Array(arr) => {
                for item in arr {
                    match item {
                        StrictJson::Object(fmap) => {
                            if let Some(tval) = fmap.get("type") {
                                if !matches!(tval, StrictJson::Str(_) | StrictJson::Null) {
                                    return Err(
                                        "Failure entry 'type' must be a string or null".to_string()
                                    );
                                }
                            }
                        }
                        _ => return Err("Verdict 'failures' elements must be objects".to_string()),
                    }
                }
            }
            _ => return Err("Verdict 'failures' must be an array".to_string()),
        }
    }
    Ok(())
}

/// Verifies a driver stdout stream containing an authenticated verdict frame (ADR-011 H2/H3).
pub fn verify_verdict_frame(
    comb_out: &str,
    parent_nonce: &str,
    parent_hmac_key: &str,
    expected_test_ids: &[String],
    exit_code: i32,
    res_status: &str,
    expected_test_hash: Option<&str>,
) -> VerdictVerificationResult {
    if comb_out.len() > MAX_VERDICT_STREAM_BYTES {
        return VerdictVerificationResult::fail_result(
            "INTEGRITY_VIOLATION",
            Some("VerdictParseError"),
            0,
            0,
            0,
            1,
        );
    }

    let start_count = comb_out.matches(VERDICT_START_MARKER).count();
    let end_count = comb_out.matches(VERDICT_END_MARKER).count();

    if start_count > 1 || end_count > 1 {
        return VerdictVerificationResult::fail_result(
            "INTEGRITY_VIOLATION",
            Some("MultipleVerdictFramesError"),
            0,
            0,
            0,
            1,
        );
    }

    if start_count != 1 || end_count != 1 {
        let status_val = if res_status == "timeout" {
            "timeout"
        } else {
            "ERROR"
        };
        return VerdictVerificationResult::fail_result(
            status_val,
            Some("DriverPreemptedError"),
            0,
            0,
            0,
            1,
        );
    }

    let start_idx = match comb_out.find(VERDICT_START_MARKER) {
        Some(idx) => idx,
        None => {
            return VerdictVerificationResult::fail_result(
                "INTEGRITY_VIOLATION",
                Some("VerdictParseError"),
                0,
                0,
                0,
                1,
            )
        }
    };
    let end_idx = match comb_out.find(VERDICT_END_MARKER) {
        Some(idx) => idx,
        None => {
            return VerdictVerificationResult::fail_result(
                "INTEGRITY_VIOLATION",
                Some("VerdictParseError"),
                0,
                0,
                0,
                1,
            )
        }
    };

    let payload_start = start_idx + VERDICT_START_MARKER.len();
    if end_idx < payload_start {
        return VerdictVerificationResult::fail_result(
            "INTEGRITY_VIOLATION",
            Some("VerdictParseError"),
            0,
            0,
            0,
            1,
        );
    }

    let raw_between = match comb_out.get(payload_start..end_idx) {
        Some(s) => python_strip(s),
        None => {
            return VerdictVerificationResult::fail_result(
                "INTEGRITY_VIOLATION",
                Some("VerdictParseError"),
                0,
                0,
                0,
                1,
            )
        }
    };

    let parsed = match parse_strict_json(
        raw_between,
        MAX_VERDICT_FRAME_BYTES,
        MAX_RECURSION_DEPTH,
        MAX_ITEM_COUNT,
        Some(MAX_COLLECTION_LENGTH),
        false,
    ) {
        Ok(StrictJson::Object(map)) => map,
        _ => {
            return VerdictVerificationResult::fail_result(
                "INTEGRITY_VIOLATION",
                Some("VerdictParseError"),
                0,
                0,
                0,
                1,
            )
        }
    };

    if validate_verdict_fields(&parsed).is_err() {
        return VerdictVerificationResult::fail_result(
            "INTEGRITY_VIOLATION",
            Some("VerdictParseError"),
            0,
            0,
            0,
            1,
        );
    }

    let received_mac = match parsed.get("mac") {
        Some(StrictJson::Str(s)) => s.as_str(),
        _ => "",
    };

    let mut payload_without_mac = BTreeMap::new();
    for (k, v) in &parsed {
        if k != "mac" {
            payload_without_mac.insert(k.clone(), v.clone());
        }
    }
    let canonical_json = StrictJson::Object(payload_without_mac).to_python_canonical_json();
    let expected_mac = hex_encode(&hmac_sha256(
        parent_hmac_key.as_bytes(),
        canonical_json.as_bytes(),
    ));

    let mac_valid = !received_mac.is_empty()
        && received_mac.is_ascii()
        && constant_time_eq(received_mac.as_bytes(), expected_mac.as_bytes());

    let discovered = extract_verdict_count(&parsed, "discovered").unwrap_or(0);
    let executed = extract_verdict_count(&parsed, "executed").unwrap_or(0);
    let failed_c = extract_verdict_count(&parsed, "failed").unwrap_or(0);
    let mut errors_c = extract_verdict_count(&parsed, "errors").unwrap_or(0);
    let mut status_val = match parsed.get("status") {
        Some(StrictJson::Str(s)) => s.clone(),
        _ => {
            if exit_code != 0 {
                "ERROR".to_string()
            } else {
                "PASS".to_string()
            }
        }
    };

    if status_val == "mutation_error" {
        return VerdictVerificationResult::fail_result(
            "mutation_error",
            Some("TestMutationError"),
            discovered,
            executed,
            failed_c,
            errors_c.max(1),
        );
    }

    if !mac_valid {
        return VerdictVerificationResult::fail_result(
            "INTEGRITY_VIOLATION",
            Some("InvalidHmacSignatureError"),
            discovered,
            executed,
            failed_c,
            errors_c.max(1),
        );
    }

    let session_nonce_matches = match parsed.get("session_nonce") {
        Some(StrictJson::Str(s)) => s.as_str() == parent_nonce,
        _ => false,
    };
    if !session_nonce_matches {
        return VerdictVerificationResult::fail_result(
            "INTEGRITY_VIOLATION",
            Some("InvalidNonceError"),
            discovered,
            executed,
            failed_c,
            errors_c.max(1),
        );
    }

    if let Some(exp_hash) = expected_test_hash {
        let hash_matches = match parsed.get("test_hash") {
            Some(StrictJson::Str(s)) => s.as_str() == exp_hash,
            _ => false,
        };
        if !hash_matches {
            return VerdictVerificationResult::fail_result(
                "mutation_error",
                Some("TestMutationError"),
                discovered,
                executed,
                failed_c,
                errors_c.max(1),
            );
        }
    }

    let mut executed_id_set: BTreeSet<String> = BTreeSet::new();
    if let Some(StrictJson::Array(arr)) = parsed.get("executed_test_ids") {
        for item in arr {
            if let StrictJson::Str(s) = item {
                executed_id_set.insert(s.clone());
            }
        }
    }
    let expected_id_set: BTreeSet<String> = expected_test_ids.iter().cloned().collect();

    let mut error_type: Option<String> = None;
    if !expected_id_set.is_empty() && executed_id_set != expected_id_set {
        status_val = "ERROR".to_string();
        errors_c = errors_c.max(1);
        error_type = Some("TestIdMismatchError".to_string());
    }

    if res_status == "timeout" {
        return VerdictVerificationResult {
            passed: false,
            status: "timeout".to_string(),
            error_type: Some(error_type.unwrap_or_else(|| "TimeoutError".to_string())),
            discovered,
            executed,
            failed: failed_c,
            errors: errors_c + 1,
        };
    }

    let is_pass = status_val == "PASS"
        && exit_code == 0
        && failed_c == 0
        && errors_c == 0
        && executed > 0
        && executed == discovered
        && session_nonce_matches
        && mac_valid
        && (expected_test_hash.is_none()
            || matches!(parsed.get("test_hash"), Some(StrictJson::Str(s)) if Some(s.as_str()) == expected_test_hash))
        && (expected_id_set.is_empty() || executed_id_set == expected_id_set);

    if !is_pass && error_type.is_none() {
        if let Some(StrictJson::Array(failures_l)) = parsed.get("failures") {
            if let Some(StrictJson::Object(first_fail)) = failures_l.first() {
                if let Some(StrictJson::Str(t_str)) = first_fail.get("type") {
                    error_type = Some(t_str.clone());
                }
            }
        }
    }

    VerdictVerificationResult {
        passed: is_pass,
        status: status_val,
        error_type,
        discovered,
        executed,
        failed: failed_c,
        errors: errors_c,
    }
}

// ============================================================================
// 6. Canonical Example Extraction (`extract_example_assertions`)
// ============================================================================

const FORBIDDEN_EXAMPLE_NAMES: &[&str] = &[
    "open",
    "eval",
    "exec",
    "compile",
    "__import__",
    "system",
    "popen",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "input",
    "breakpoint",
    "print",
    "int",
    "float",
    "str",
    "bytes",
    "bool",
    "list",
    "tuple",
    "set",
    "dict",
    "frozenset",
    "type",
    "object",
    "super",
    "os",
    "sys",
    "subprocess",
    "shutil",
    "pathlib",
    "socket",
    "urllib",
];

fn is_forbidden_example_name(name: &str) -> bool {
    FORBIDDEN_EXAMPLE_NAMES.contains(&name)
}

fn is_ident_start(c: char) -> bool {
    if c.is_ascii_alphabetic() || c == '_' {
        return true;
    }
    let cp = c as u32;
    if (0x0D80..=0x0DFF).contains(&cp) {
        return c.is_alphabetic();
    }
    false
}

fn is_ident_continue(c: char) -> bool {
    if c.is_ascii_alphanumeric() || c == '_' {
        return true;
    }
    let cp = c as u32;
    if (0x0D80..=0x0DFF).contains(&cp) {
        return c.is_alphabetic()
            || matches!(
                cp,
                0x0D81..=0x0D83
                    | 0x0DCA
                    | 0x0DCF..=0x0DD6
                    | 0x0DD8..=0x0DDF
                    | 0x0DE6..=0x0DEF
                    | 0x0DF2..=0x0DF3
            );
    }
    if matches!(cp, 0x200C | 0x200D) {
        return true;
    }
    false
}

fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_ident_start(first) {
        return false;
    }
    chars.all(is_ident_continue)
}


fn python_splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut line_start = 0;
    let mut iter = s.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        let is_break = matches!(
            ch,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if is_break {
            if let Some(seg) = s.get(line_start..idx) {
                lines.push(seg);
            }
            if ch == '\r' {
                if let Some(&(_, '\n')) = iter.peek() {
                    iter.next();
                }
            }
            line_start = iter.peek().map(|&(next_i, _)| next_i).unwrap_or(s.len());
        }
    }
    if line_start < s.len() {
        if let Some(seg) = s.get(line_start..) {
            lines.push(seg);
        }
    }
    lines
}

fn split_code_and_comment(text: &str) -> (String, String) {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
        } else if ch == '\'' || ch == '"' {
            in_quote = Some(ch);
        } else if ch == '#' {
            let left = text.get(..idx).map(python_strip).unwrap_or("");
            let right = text.get(idx + 1..).map(python_strip).unwrap_or("");
            return (left.to_string(), right.to_string());
        }
    }
    (python_strip(text).to_string(), String::new())
}

fn infer_entry_point(prompt: &str, section: &str) -> Option<String> {
    let marker = if prompt.contains("Example:") {
        "Example:"
    } else {
        "Examples:"
    };
    let header = prompt
        .split_once(marker)
        .map(|(h, _)| h)
        .unwrap_or(prompt);

    // Pattern 1: \bdef\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(
    for m in find_keyword_ident_matches(header, "def", true) {
        if !m.starts_with('_') && !is_forbidden_example_name(&m) {
            return Some(m);
        }
    }
    // Pattern 2: `([a-zA-Z_][a-zA-Z0-9_]*)\s*\(
    for m in find_backtick_call_matches(header) {
        if !m.starts_with('_') && !is_forbidden_example_name(&m) {
            return Some(m);
        }
    }
    // Pattern 3: \bfunction\s+`?([a-zA-Z_][a-zA-Z0-9_]*)\b
    for m in find_keyword_ident_matches(header, "function", false) {
        if !m.starts_with('_') && !is_forbidden_example_name(&m) {
            return Some(m);
        }
    }
    // Fallback in section: ^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(
    for line in section.split('\n') {
        let trimmed = python_strip(line);
        let mut chars = trimmed.char_indices();
        let Some((_, first)) = chars.next() else {
            continue;
        };
        if !is_ident_start(first) {
            continue;
        }
        let mut end_idx = first.len_utf8();
        for (i, c) in chars {
            if is_ident_continue(c) {
                end_idx = i + c.len_utf8();
            } else {
                break;
            }
        }
        let Some(ident) = trimmed.get(..end_idx) else {
            continue;
        };
        let rest = trimmed.get(end_idx..).map(python_strip).unwrap_or("");
        if rest.starts_with('(') && !ident.starts_with('_') && !is_forbidden_example_name(ident) {
            return Some(ident.to_string());
        }
    }

    None
}

fn find_keyword_ident_matches(text: &str, kw: &str, require_open_paren: bool) -> Vec<String> {
    let mut results = Vec::new();
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (byte_pos, ch) = chars[i];
        let prev_is_word = if i > 0 {
            is_ident_continue(chars[i - 1].1)
        } else {
            false
        };
        if !prev_is_word && text.get(byte_pos..).is_some_and(|s| s.starts_with(kw)) {
            let after_kw_byte = byte_pos + kw.len();
            let after_slice = text.get(after_kw_byte..).unwrap_or("");
            let mut after_chars = after_slice.char_indices().peekable();
            if let Some(&(_, first_after)) = after_chars.peek() {
                if is_python_whitespace(first_after) {
                    while let Some(&(_, c)) = after_chars.peek() {
                        if is_python_whitespace(c) {
                            after_chars.next();
                        } else {
                            break;
                        }
                    }
                    if !require_open_paren {
                        if let Some(&(_, '`')) = after_chars.peek() {
                            after_chars.next();
                        }
                    }
                    if let Some(&(id_start_rel, id_first)) = after_chars.peek() {
                        if is_ident_start(id_first) {
                            let id_start = after_kw_byte + id_start_rel;
                            let mut id_end = id_start + id_first.len_utf8();
                            after_chars.next();
                            while let Some(&(rel_i, c)) = after_chars.peek() {
                                if is_ident_continue(c) {
                                    id_end = after_kw_byte + rel_i + c.len_utf8();
                                    after_chars.next();
                                } else {
                                    break;
                                }
                            }
                            if let Some(ident) = text.get(id_start..id_end) {
                                if require_open_paren {
                                    while let Some(&(_, c)) = after_chars.peek() {
                                        if is_python_whitespace(c) {
                                            after_chars.next();
                                        } else {
                                            break;
                                        }
                                    }
                                    if matches!(after_chars.peek(), Some(&(_, '('))) {
                                        results.push(ident.to_string());
                                    }
                                } else {
                                    results.push(ident.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = ch;
        i += 1;
    }
    results
}

fn find_backtick_call_matches(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    for (byte_pos, ch) in text.char_indices() {
        if ch == '`' {
            let after_bt = text.get(byte_pos + 1..).unwrap_or("");
            let mut chars = after_bt.char_indices().peekable();
            if let Some(&(_, first)) = chars.peek() {
                if is_ident_start(first) {
                    let mut id_end = first.len_utf8();
                    chars.next();
                    while let Some(&(rel_i, c)) = chars.peek() {
                        if is_ident_continue(c) {
                            id_end = rel_i + c.len_utf8();
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if let Some(ident) = after_bt.get(..id_end) {
                        while let Some(&(_, c)) = chars.peek() {
                            if is_python_whitespace(c) {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        if matches!(chars.peek(), Some(&(_, '('))) {
                            results.push(ident.to_string());
                        }
                    }
                }
            }
        }
    }
    results
}

fn has_approx_marker(comment: &str) -> bool {
    if comment.contains('~') {
        return true;
    }
    let mut current_word = String::new();
    for ch in comment.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current_word.push(ch.to_ascii_lowercase());
        } else {
            if matches!(
                current_word.as_str(),
                "approx" | "approximately" | "roughly" | "about" | "estimate" | "rounded"
            ) {
                return true;
            }
            current_word.clear();
        }
    }
    matches!(
        current_word.as_str(),
        "approx" | "approximately" | "roughly" | "about" | "estimate" | "rounded"
    )
}

// ============================================================================
// 7. Python Expression Subset Lexer & AST for `extract_example_assertions`
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum PyTokKind {
    Ident(String),
    Int(u64),
    OutOfRangeInt,
    Float(f64),
    Str(String),
    BytesLit,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Assign,
    Plus,
    Minus,
    EqEq,
    Gt,
    Lt,
    GtEq,
    LtEq,
}

#[derive(Debug, Clone)]
struct PyTok {
    kind: PyTokKind,
    start: usize,
    end: usize,
}

fn is_python_keyword(ident: &str) -> bool {
    matches!(
        ident,
        "False"
            | "None"
            | "True"
            | "and"
            | "as"
            | "assert"
            | "async"
            | "await"
            | "break"
            | "class"
            | "continue"
            | "def"
            | "del"
            | "elif"
            | "else"
            | "except"
            | "finally"
            | "for"
            | "from"
            | "global"
            | "if"
            | "import"
            | "in"
            | "is"
            | "lambda"
            | "nonlocal"
            | "not"
            | "or"
            | "pass"
            | "raise"
            | "return"
            | "try"
            | "while"
            | "with"
            | "yield"
    )
}

fn tokenize_py_expr(src: &str) -> Result<Vec<PyTok>, ()> {
    if src.contains('\0') {
        return Err(());
    }
    let bytes = src.as_bytes();
    let mut pos = 0;
    let mut tokens = Vec::new();

    while pos < bytes.len() {
        let rest = src.get(pos..).ok_or(())?;
        let first_ch = rest.chars().next().ok_or(())?;
        if is_python_whitespace(first_ch) {
            pos += first_ch.len_utf8();
            continue;
        }

        let start = pos;
        let b = bytes.get(pos).copied().ok_or(())?;

        // Check string or byte literal with 2-char prefix rb/br (case-insensitive)
        if let (Some(&b1), Some(&b2), Some(&b3)) = (bytes.get(pos), bytes.get(pos + 1), bytes.get(pos + 2)) {
            let is_rb = matches!((b1, b2), (b'r' | b'R', b'b' | b'B') | (b'b' | b'B', b'r' | b'R'));
            if is_rb && matches!(b3, b'\'' | b'"') {
                pos += 2;
                let _ = consume_py_quoted_string(src, &mut pos, true)?;
                tokens.push(PyTok {
                    kind: PyTokKind::BytesLit,
                    start,
                    end: pos,
                });
                continue;
            }
        }

        // Check string or byte literal with optional prefix b/B/r/R/u/U
        if matches!(b, b'b' | b'B' | b'r' | b'R' | b'u' | b'U') {
            let next_b = bytes.get(pos + 1).copied();
            if matches!(next_b, Some(b'\'' | b'"')) {
                let is_bytes = matches!(b, b'b' | b'B');
                let is_raw = matches!(b, b'r' | b'R');
                pos += 1;
                let content = consume_py_quoted_string(src, &mut pos, is_raw)?;
                let kind = if is_bytes {
                    PyTokKind::BytesLit
                } else {
                    PyTokKind::Str(content)
                };
                tokens.push(PyTok {
                    kind,
                    start,
                    end: pos,
                });
                continue;
            }
        }

        match b {
            b'\'' | b'"' => {
                let content = consume_py_quoted_string(src, &mut pos, false)?;
                tokens.push(PyTok {
                    kind: PyTokKind::Str(content),
                    start,
                    end: pos,
                });
            }
            b'(' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::LParen,
                    start,
                    end: pos,
                });
            }
            b')' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::RParen,
                    start,
                    end: pos,
                });
            }
            b'[' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::LBracket,
                    start,
                    end: pos,
                });
            }
            b']' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::RBracket,
                    start,
                    end: pos,
                });
            }
            b'{' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::LBrace,
                    start,
                    end: pos,
                });
            }
            b'}' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::RBrace,
                    start,
                    end: pos,
                });
            }
            b',' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::Comma,
                    start,
                    end: pos,
                });
            }
            b':' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    return Err(());
                }
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::Colon,
                    start,
                    end: pos,
                });
            }
            b'+' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::Plus,
                    start,
                    end: pos,
                });
            }
            b'-' => {
                pos += 1;
                tokens.push(PyTok {
                    kind: PyTokKind::Minus,
                    start,
                    end: pos,
                });
            }
            b'=' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    tokens.push(PyTok {
                        kind: PyTokKind::EqEq,
                        start,
                        end: pos,
                    });
                } else {
                    pos += 1;
                    tokens.push(PyTok {
                        kind: PyTokKind::Assign,
                        start,
                        end: pos,
                    });
                }
            }
            b'>' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    tokens.push(PyTok {
                        kind: PyTokKind::GtEq,
                        start,
                        end: pos,
                    });
                } else if bytes.get(pos + 1) == Some(&b'>') {
                    return Err(());
                } else {
                    pos += 1;
                    tokens.push(PyTok {
                        kind: PyTokKind::Gt,
                        start,
                        end: pos,
                    });
                }
            }
            b'<' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    tokens.push(PyTok {
                        kind: PyTokKind::LtEq,
                        start,
                        end: pos,
                    });
                } else if bytes.get(pos + 1) == Some(&b'<') {
                    return Err(());
                } else {
                    pos += 1;
                    tokens.push(PyTok {
                        kind: PyTokKind::Lt,
                        start,
                        end: pos,
                    });
                }
            }
            b'0'..=b'9' | b'.' => {
                let tok_kind = consume_py_number(src, &mut pos)?;
                tokens.push(PyTok {
                    kind: tok_kind,
                    start,
                    end: pos,
                });
            }
            _ if is_ident_start(first_ch) => {
                pos += first_ch.len_utf8();
                while let Some(rem) = src.get(pos..) {
                    if let Some(c) = rem.chars().next() {
                        if is_ident_continue(c) {
                            pos += c.len_utf8();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                let ident = src.get(start..pos).ok_or(())?.to_string();
                tokens.push(PyTok {
                    kind: PyTokKind::Ident(ident),
                    start,
                    end: pos,
                });
            }
            _ => return Err(()),
        }
    }

    Ok(tokens)
}

fn consume_py_quoted_string(src: &str, pos: &mut usize, is_raw: bool) -> Result<String, ()> {
    let bytes = src.as_bytes();
    let q = bytes.get(*pos).copied().ok_or(())?;
    let is_triple = bytes.get(*pos..*pos + 3) == Some(&[q, q, q]);
    if is_triple {
        *pos += 3;
    } else {
        *pos += 1;
    }
    let mut out = String::new();
    while *pos < bytes.len() {
        if is_triple {
            if bytes.get(*pos..*pos + 3) == Some(&[q, q, q]) {
                *pos += 3;
                return Ok(out);
            }
        } else if bytes.get(*pos) == Some(&q) {
            *pos += 1;
            return Ok(out);
        }

        let b = bytes.get(*pos).copied().ok_or(())?;
        if is_raw {
            if b == b'\\' {
                let next_b = bytes.get(*pos + 1).copied();
                if next_b == Some(q) {
                    out.push('\\');
                    out.push(q as char);
                    *pos += 2;
                    continue;
                }
            }
            let tail = src.get(*pos..).ok_or(())?;
            let ch = tail.chars().next().ok_or(())?;
            if ch == '\0' {
                return Err(());
            }
            if !is_triple && (ch == '\n' || ch == '\r') {
                return Err(());
            }
            out.push(ch);
            *pos += ch.len_utf8();
            continue;
        }

        if b == b'\\' {
            *pos += 1;
            let esc_b = bytes.get(*pos).copied().ok_or(())?;
            match esc_b {
                b'\n' => {
                    *pos += 1;
                }
                b'\r' => {
                    *pos += 1;
                    if bytes.get(*pos) == Some(&b'\n') {
                        *pos += 1;
                    }
                }
                b'n' => {
                    *pos += 1;
                    out.push('\n');
                }
                b'r' => {
                    *pos += 1;
                    out.push('\r');
                }
                b't' => {
                    *pos += 1;
                    out.push('\t');
                }
                b'\\' => {
                    *pos += 1;
                    out.push('\\');
                }
                b'\'' => {
                    *pos += 1;
                    out.push('\'');
                }
                b'"' => {
                    *pos += 1;
                    out.push('"');
                }
                b'a' => {
                    *pos += 1;
                    out.push('\x07');
                }
                b'b' => {
                    *pos += 1;
                    out.push('\x08');
                }
                b'f' => {
                    *pos += 1;
                    out.push('\x0c');
                }
                b'v' => {
                    *pos += 1;
                    out.push('\x0b');
                }
                b'0'..=b'7' => {
                    let mut val = 0u32;
                    let mut digits = 0;
                    while digits < 3 {
                        if let Some(&oct_b) = bytes.get(*pos) {
                            if matches!(oct_b, b'0'..=b'7') {
                                val = val * 8 + (oct_b - b'0') as u32;
                                *pos += 1;
                                digits += 1;
                                continue;
                            }
                        }
                        break;
                    }
                    if val == 0 {
                        return Err(());
                    }
                    let ch = char::from_u32(val).ok_or(())?;
                    out.push(ch);
                }
                b'x' => {
                    *pos += 1;
                    let h1 = bytes.get(*pos).copied().ok_or(())?;
                    let h2 = bytes.get(*pos + 1).copied().ok_or(())?;
                    if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                        return Err(());
                    }
                    *pos += 2;
                    let hex_bytes = [h1, h2];
                    let hex_slice = std::str::from_utf8(&hex_bytes).map_err(|_| ())?;
                    let hex_val = u8::from_str_radix(hex_slice, 16).map_err(|_| ())?;
                    if hex_val == 0 {
                        return Err(());
                    }
                    out.push(hex_val as char);
                }
                b'u' => {
                    *pos += 1;
                    let slice = bytes.get(*pos..*pos + 4).ok_or(())?;
                    if !slice.iter().all(|c| c.is_ascii_hexdigit()) {
                        return Err(());
                    }
                    *pos += 4;
                    let hex_str = std::str::from_utf8(slice).map_err(|_| ())?;
                    let cp = u32::from_str_radix(hex_str, 16).map_err(|_| ())?;
                    if cp == 0 || (0xD800..=0xDFFF).contains(&cp) {
                        return Err(());
                    }
                    let ch = char::from_u32(cp).ok_or(())?;
                    out.push(ch);
                }
                b'U' => {
                    *pos += 1;
                    let slice = bytes.get(*pos..*pos + 8).ok_or(())?;
                    if !slice.iter().all(|c| c.is_ascii_hexdigit()) {
                        return Err(());
                    }
                    *pos += 8;
                    let hex_str = std::str::from_utf8(slice).map_err(|_| ())?;
                    let cp = u32::from_str_radix(hex_str, 16).map_err(|_| ())?;
                    if cp == 0 || cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) {
                        return Err(());
                    }
                    let ch = char::from_u32(cp).ok_or(())?;
                    out.push(ch);
                }
                b'N' => {
                    return Err(());
                }
                _ => {
                    let tail = src.get(*pos..).ok_or(())?;
                    let esc_ch = tail.chars().next().ok_or(())?;
                    *pos += esc_ch.len_utf8();
                    out.push('\\');
                    out.push(esc_ch);
                }
            }
        } else {
            let tail = src.get(*pos..).ok_or(())?;
            let ch = tail.chars().next().ok_or(())?;
            if (ch as u32) < 0x20 {
                if ch == '\t' {
                    // allowed
                } else if is_triple && (ch == '\n' || ch == '\r') {
                    // allowed in triple-quoted string
                } else {
                    return Err(());
                }
            }
            out.push(ch);
            *pos += ch.len_utf8();
        }
    }
    Err(())
}

fn consume_py_number(src: &str, pos: &mut usize) -> Result<PyTokKind, ()> {
    let bytes = src.as_bytes();
    let start = *pos;

    // Check 0x / 0o / 0b integer prefixes
    if bytes.get(*pos) == Some(&b'0') {
        if let Some(&prefix) = bytes.get(*pos + 1) {
            let radix = match prefix {
                b'x' | b'X' => Some(16),
                b'o' | b'O' => Some(8),
                b'b' | b'B' => Some(2),
                _ => None,
            };
            if let Some(r) = radix {
                *pos += 2;
                let dig_start = *pos;
                while let Some(&b) = bytes.get(*pos) {
                    let valid_dig = match r {
                        16 => b.is_ascii_hexdigit() || b == b'_',
                        8 => (b'0'..=b'7').contains(&b) || b == b'_',
                        2 => b == b'0' || b == b'1' || b == b'_',
                        _ => false,
                    };
                    if valid_dig {
                        *pos += 1;
                    } else {
                        break;
                    }
                }
                let raw_digits = src.get(dig_start..*pos).ok_or(())?;
                if raw_digits.is_empty()
                    || raw_digits.ends_with('_')
                    || raw_digits.contains("__")
                {
                    return Err(());
                }
                let clean: String = raw_digits.chars().filter(|&c| c != '_').collect();
                if clean.is_empty() {
                    return Err(());
                }
                return match u64::from_str_radix(&clean, r) {
                    Ok(v) => Ok(PyTokKind::Int(v)),
                    Err(_) => Ok(PyTokKind::OutOfRangeInt),
                };
            }
        }
    }

    let mut is_float = false;
    if bytes.get(*pos) == Some(&b'.') {
        is_float = true;
        *pos += 1;
        if !matches!(bytes.get(*pos), Some(b'0'..=b'9')) {
            return Err(());
        }
        while matches!(bytes.get(*pos), Some(b'0'..=b'9' | b'_')) {
            *pos += 1;
        }
    } else {
        while matches!(bytes.get(*pos), Some(b'0'..=b'9' | b'_')) {
            *pos += 1;
        }
        if bytes.get(*pos) == Some(&b'.') {
            is_float = true;
            *pos += 1;
            while matches!(bytes.get(*pos), Some(b'0'..=b'9' | b'_')) {
                *pos += 1;
            }
        }
    }

    if matches!(bytes.get(*pos), Some(b'e' | b'E')) {
        is_float = true;
        *pos += 1;
        if matches!(bytes.get(*pos), Some(b'+' | b'-')) {
            *pos += 1;
        }
        if !matches!(bytes.get(*pos), Some(b'0'..=b'9')) {
            return Err(());
        }
        while matches!(bytes.get(*pos), Some(b'0'..=b'9' | b'_')) {
            *pos += 1;
        }
    }

    // Reject trailing identifier characters like `123abc` or `10j`
    if let Some(rem) = src.get(*pos..) {
        if let Some(next_ch) = rem.chars().next() {
            if is_ident_start(next_ch) {
                return Err(());
            }
        }
    }

    let raw_tok = src.get(start..*pos).ok_or(())?;
    if raw_tok.starts_with('_')
        || raw_tok.ends_with('_')
        || raw_tok.contains("__")
        || raw_tok.contains("_.")
        || raw_tok.contains("._")
        || raw_tok.contains("_e")
        || raw_tok.contains("_E")
        || raw_tok.contains("e_")
        || raw_tok.contains("E_")
        || raw_tok.contains("+_")
        || raw_tok.contains("-_")
    {
        return Err(());
    }

    let clean: String = raw_tok.chars().filter(|&c| c != '_').collect();
    if is_float {
        let f = clean.parse::<f64>().map_err(|_| ())?;
        Ok(PyTokKind::Float(f))
    } else {
        // Reject leading zeros on non-zero decimal integer literals (e.g. `01`)
        if clean.starts_with('0') && clean.chars().any(|c| c != '0') {
            return Err(());
        }
        if clean.len() > 32 {
            return Ok(PyTokKind::OutOfRangeInt);
        }
        match clean.parse::<u64>() {
            Ok(v) => Ok(PyTokKind::Int(v)),
            Err(_) => Ok(PyTokKind::OutOfRangeInt),
        }
    }
}

#[derive(Debug, Clone)]
enum PyAstKind {
    Bool,
    None,
    Int(u64),
    OutOfRangeInt,
    Float(f64),
    Str(String),
    Bytes,
    Name(String),
    Unary {
        is_neg: bool,
        operand: Box<PyAstNode>,
    },
    List(Vec<PyAstNode>),
    Tuple(Vec<PyAstNode>),
    Set(Vec<PyAstNode>),
    Dict(Vec<(PyAstNode, PyAstNode)>),
    Call {
        func: String,
        args: Vec<PyAstNode>,
        keywords: Vec<(String, PyAstNode)>,
    },
    Compare {
        left: Box<PyAstNode>,
        op: PyCmpOp,
        right: Box<PyAstNode>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PyCmpOp {
    Eq,
    Gt,
    Lt,
    GtE,
    LtE,
}

#[derive(Debug, Clone)]
struct PyAstNode {
    kind: PyAstKind,
    start: usize,
    end: usize,
}

struct PyParser<'a> {
    tokens: &'a [PyTok],
    pos: usize,
}

impl<'a> PyParser<'a> {
    fn new(tokens: &'a [PyTok]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&'a PyTok> {
        self.tokens.get(self.pos)
    }

    fn next_tok(&mut self) -> Option<&'a PyTok> {
        let tok = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(tok)
    }

    fn parse_eval_expr(&mut self) -> Result<PyAstNode, ()> {
        let node = self.parse_tuple_or_compare(0)?;
        if self.pos != self.tokens.len() {
            return Err(());
        }
        Ok(node)
    }

    fn parse_tuple_or_compare(&mut self, depth: usize) -> Result<PyAstNode, ()> {
        if depth > MAX_RECURSION_DEPTH + 4 {
            return Err(());
        }
        let first = self.parse_compare(depth)?;
        if matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Comma)) {
            let start = first.start;
            let mut end = first.end;
            let mut elts = vec![first];
            while matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Comma)) {
                let comma_tok = self.next_tok().ok_or(())?;
                end = comma_tok.end;
                if self.pos >= self.tokens.len() {
                    break;
                }
                let next_elt = self.parse_compare(depth + 1)?;
                end = next_elt.end;
                elts.push(next_elt);
                if elts.len() > MAX_COLLECTION_LENGTH + 1 {
                    return Err(());
                }
            }
            return Ok(PyAstNode {
                kind: PyAstKind::Tuple(elts),
                start,
                end,
            });
        }
        Ok(first)
    }

    fn parse_compare(&mut self, depth: usize) -> Result<PyAstNode, ()> {
        let left = self.parse_atom_or_unary(depth)?;
        let op = match self.peek().map(|t| &t.kind) {
            Some(PyTokKind::EqEq) => Some(PyCmpOp::Eq),
            Some(PyTokKind::Gt) => Some(PyCmpOp::Gt),
            Some(PyTokKind::Lt) => Some(PyCmpOp::Lt),
            Some(PyTokKind::GtEq) => Some(PyCmpOp::GtE),
            Some(PyTokKind::LtEq) => Some(PyCmpOp::LtE),
            _ => None,
        };
        if let Some(cmp_op) = op {
            self.next_tok();
            let right = self.parse_atom_or_unary(depth + 1)?;
            // Reject chained comparisons like `a < b < c`
            if matches!(
                self.peek().map(|t| &t.kind),
                Some(
                    PyTokKind::EqEq
                        | PyTokKind::Gt
                        | PyTokKind::Lt
                        | PyTokKind::GtEq
                        | PyTokKind::LtEq
                )
            ) {
                return Err(());
            }
            let start = left.start;
            let end = right.end;
            return Ok(PyAstNode {
                kind: PyAstKind::Compare {
                    left: Box::new(left),
                    op: cmp_op,
                    right: Box::new(right),
                },
                start,
                end,
            });
        }
        Ok(left)
    }

    fn parse_atom_or_unary(&mut self, depth: usize) -> Result<PyAstNode, ()> {
        if depth > MAX_RECURSION_DEPTH + 4 {
            return Err(());
        }
        let tok = self.peek().ok_or(())?;
        match &tok.kind {
            PyTokKind::Plus | PyTokKind::Minus => {
                let op_tok = self.next_tok().ok_or(())?;
                let is_neg = matches!(op_tok.kind, PyTokKind::Minus);
                let operand = self.parse_atom_or_unary(depth + 1)?;
                let start = op_tok.start;
                let end = operand.end;
                Ok(PyAstNode {
                    kind: PyAstKind::Unary {
                        is_neg,
                        operand: Box::new(operand),
                    },
                    start,
                    end,
                })
            }
            PyTokKind::Int(v) => {
                let t = self.next_tok().ok_or(())?;
                Ok(PyAstNode {
                    kind: PyAstKind::Int(*v),
                    start: t.start,
                    end: t.end,
                })
            }
            PyTokKind::OutOfRangeInt => {
                let t = self.next_tok().ok_or(())?;
                Ok(PyAstNode {
                    kind: PyAstKind::OutOfRangeInt,
                    start: t.start,
                    end: t.end,
                })
            }
            PyTokKind::Float(f) => {
                let t = self.next_tok().ok_or(())?;
                Ok(PyAstNode {
                    kind: PyAstKind::Float(*f),
                    start: t.start,
                    end: t.end,
                })
            }
            PyTokKind::Str(_) => {
                let first_t = self.next_tok().ok_or(())?;
                let mut combined = match &first_t.kind {
                    PyTokKind::Str(s) => s.clone(),
                    _ => unreachable!(),
                };
                let mut end = first_t.end;
                // Adjacent string literal concatenation in Python (`"a" "b"`)
                while let Some(PyTok {
                    kind: PyTokKind::Str(next_s),
                    end: next_end,
                    ..
                }) = self.peek()
                {
                    combined.push_str(next_s);
                    end = *next_end;
                    self.next_tok();
                }
                Ok(PyAstNode {
                    kind: PyAstKind::Str(combined),
                    start: first_t.start,
                    end,
                })
            }
            PyTokKind::BytesLit => {
                let first_t = self.next_tok().ok_or(())?;
                let mut end = first_t.end;
                while let Some(PyTok {
                    kind: PyTokKind::BytesLit,
                    end: next_end,
                    ..
                }) = self.peek()
                {
                    end = *next_end;
                    self.next_tok();
                }
                Ok(PyAstNode {
                    kind: PyAstKind::Bytes,
                    start: first_t.start,
                    end,
                })
            }
            PyTokKind::Ident(ident) => {
                let t = self.next_tok().ok_or(())?;
                match ident.as_str() {
                    "True" | "False" => Ok(PyAstNode {
                        kind: PyAstKind::Bool,
                        start: t.start,
                        end: t.end,
                    }),
                    "None" => Ok(PyAstNode {
                        kind: PyAstKind::None,
                        start: t.start,
                        end: t.end,
                    }),
                    name if is_python_keyword(name) => Err(()),
                    name => {
                        if matches!(self.peek().map(|p| &p.kind), Some(PyTokKind::LParen)) {
                            self.parse_call(name.to_string(), t.start, depth + 1)
                        } else {
                            Ok(PyAstNode {
                                kind: PyAstKind::Name(name.to_string()),
                                start: t.start,
                                end: t.end,
                            })
                        }
                    }
                }
            }
            PyTokKind::LParen => self.parse_paren_or_tuple(depth + 1),
            PyTokKind::LBracket => self.parse_list(depth + 1),
            PyTokKind::LBrace => self.parse_set_or_dict(depth + 1),
            _ => Err(()),
        }
    }

    fn parse_call(
        &mut self,
        func: String,
        start: usize,
        depth: usize,
    ) -> Result<PyAstNode, ()> {
        self.next_tok(); // consume '('
        let mut args = Vec::new();
        let mut keywords = Vec::new();
        let mut seen_kw = false;

        if let Some(PyTok {
            kind: PyTokKind::RParen,
            end,
            ..
        }) = self.peek()
        {
            let end_pos = *end;
            self.next_tok();
            return Ok(PyAstNode {
                kind: PyAstKind::Call {
                    func,
                    args,
                    keywords,
                },
                start,
                end: end_pos,
            });
        }

        loop {
            // Check keyword argument `ident = expr`
            let is_kw = matches!(
                (self.tokens.get(self.pos), self.tokens.get(self.pos + 1)),
                (
                    Some(PyTok {
                        kind: PyTokKind::Ident(_),
                        ..
                    }),
                    Some(PyTok {
                        kind: PyTokKind::Assign,
                        ..
                    })
                )
            );
            if is_kw {
                seen_kw = true;
                let kw_tok = self.next_tok().ok_or(())?;
                let kw_name = match &kw_tok.kind {
                    PyTokKind::Ident(s) if !is_python_keyword(s) => s.clone(),
                    _ => return Err(()),
                };
                self.next_tok(); // consume '='
                let val_node = self.parse_compare(depth + 1)?;
                if keywords.iter().any(|(k, _)| k == &kw_name) {
                    return Err(());
                }
                keywords.push((kw_name, val_node));
            } else {
                if seen_kw {
                    return Err(());
                }
                let arg_node = self.parse_compare(depth + 1)?;
                args.push(arg_node);
            }

            if args.len() > MAX_COLLECTION_LENGTH || keywords.len() > MAX_COLLECTION_LENGTH {
                return Err(());
            }

            match self.peek() {
                Some(PyTok {
                    kind: PyTokKind::Comma,
                    ..
                }) => {
                    self.next_tok();
                    if let Some(PyTok {
                        kind: PyTokKind::RParen,
                        end,
                        ..
                    }) = self.peek()
                    {
                        let end_pos = *end;
                        self.next_tok();
                        return Ok(PyAstNode {
                            kind: PyAstKind::Call {
                                func,
                                args,
                                keywords,
                            },
                            start,
                            end: end_pos,
                        });
                    }
                }
                Some(PyTok {
                    kind: PyTokKind::RParen,
                    end,
                    ..
                }) => {
                    let end_pos = *end;
                    self.next_tok();
                    return Ok(PyAstNode {
                        kind: PyAstKind::Call {
                            func,
                            args,
                            keywords,
                        },
                        start,
                        end: end_pos,
                    });
                }
                _ => return Err(()),
            }
        }
    }

    fn parse_paren_or_tuple(&mut self, depth: usize) -> Result<PyAstNode, ()> {
        let open_tok = self.next_tok().ok_or(())?;
        let start = open_tok.start;
        if let Some(PyTok {
            kind: PyTokKind::RParen,
            end,
            ..
        }) = self.peek()
        {
            let end_pos = *end;
            self.next_tok();
            return Ok(PyAstNode {
                kind: PyAstKind::Tuple(Vec::new()),
                start,
                end: end_pos,
            });
        }

        let mut first = self.parse_compare(depth)?;
        if let Some(PyTok {
            kind: PyTokKind::RParen,
            end,
            ..
        }) = self.peek()
        {
            let end_pos = *end;
            self.next_tok();
            first.start = start;
            first.end = end_pos;
            return Ok(first);
        }

        let mut elts = vec![first];
        while matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Comma)) {
            self.next_tok();
            if let Some(PyTok {
                kind: PyTokKind::RParen,
                end,
                ..
            }) = self.peek()
            {
                let end_pos = *end;
                self.next_tok();
                return Ok(PyAstNode {
                    kind: PyAstKind::Tuple(elts),
                    start,
                    end: end_pos,
                });
            }
            let next_elt = self.parse_compare(depth)?;
            elts.push(next_elt);
            if elts.len() > MAX_COLLECTION_LENGTH + 1 {
                return Err(());
            }
        }

        if let Some(PyTok {
            kind: PyTokKind::RParen,
            end,
            ..
        }) = self.peek()
        {
            let end_pos = *end;
            self.next_tok();
            Ok(PyAstNode {
                kind: PyAstKind::Tuple(elts),
                start,
                end: end_pos,
            })
        } else {
            Err(())
        }
    }

    fn parse_list(&mut self, depth: usize) -> Result<PyAstNode, ()> {
        let open_tok = self.next_tok().ok_or(())?;
        let start = open_tok.start;
        let mut elts = Vec::new();
        if let Some(PyTok {
            kind: PyTokKind::RBracket,
            end,
            ..
        }) = self.peek()
        {
            let end_pos = *end;
            self.next_tok();
            return Ok(PyAstNode {
                kind: PyAstKind::List(elts),
                start,
                end: end_pos,
            });
        }
        loop {
            let elt = self.parse_compare(depth)?;
            elts.push(elt);
            if elts.len() > MAX_COLLECTION_LENGTH + 1 {
                return Err(());
            }
            match self.peek() {
                Some(PyTok {
                    kind: PyTokKind::Comma,
                    ..
                }) => {
                    self.next_tok();
                    if let Some(PyTok {
                        kind: PyTokKind::RBracket,
                        end,
                        ..
                    }) = self.peek()
                    {
                        let end_pos = *end;
                        self.next_tok();
                        return Ok(PyAstNode {
                            kind: PyAstKind::List(elts),
                            start,
                            end: end_pos,
                        });
                    }
                }
                Some(PyTok {
                    kind: PyTokKind::RBracket,
                    end,
                    ..
                }) => {
                    let end_pos = *end;
                    self.next_tok();
                    return Ok(PyAstNode {
                        kind: PyAstKind::List(elts),
                        start,
                        end: end_pos,
                    });
                }
                _ => return Err(()),
            }
        }
    }

    fn parse_set_or_dict(&mut self, depth: usize) -> Result<PyAstNode, ()> {
        let open_tok = self.next_tok().ok_or(())?;
        let start = open_tok.start;
        if let Some(PyTok {
            kind: PyTokKind::RBrace,
            end,
            ..
        }) = self.peek()
        {
            let end_pos = *end;
            self.next_tok();
            return Ok(PyAstNode {
                kind: PyAstKind::Dict(Vec::new()),
                start,
                end: end_pos,
            });
        }

        let first = self.parse_compare(depth)?;
        if matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Colon)) {
            self.next_tok(); // consume ':'
            let first_val = self.parse_compare(depth)?;
            let mut pairs = vec![(first, first_val)];
            while matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Comma)) {
                self.next_tok();
                if let Some(PyTok {
                    kind: PyTokKind::RBrace,
                    end,
                    ..
                }) = self.peek()
                {
                    let end_pos = *end;
                    self.next_tok();
                    return Ok(PyAstNode {
                        kind: PyAstKind::Dict(pairs),
                        start,
                        end: end_pos,
                    });
                }
                let k = self.parse_compare(depth)?;
                if !matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Colon)) {
                    return Err(());
                }
                self.next_tok();
                let v = self.parse_compare(depth)?;
                pairs.push((k, v));
                if pairs.len() > MAX_COLLECTION_LENGTH + 1 {
                    return Err(());
                }
            }
            if let Some(PyTok {
                kind: PyTokKind::RBrace,
                end,
                ..
            }) = self.peek()
            {
                let end_pos = *end;
                self.next_tok();
                Ok(PyAstNode {
                    kind: PyAstKind::Dict(pairs),
                    start,
                    end: end_pos,
                })
            } else {
                Err(())
            }
        } else {
            let mut elts = vec![first];
            while matches!(self.peek().map(|t| &t.kind), Some(PyTokKind::Comma)) {
                self.next_tok();
                if let Some(PyTok {
                    kind: PyTokKind::RBrace,
                    end,
                    ..
                }) = self.peek()
                {
                    let end_pos = *end;
                    self.next_tok();
                    return Ok(PyAstNode {
                        kind: PyAstKind::Set(elts),
                        start,
                        end: end_pos,
                    });
                }
                let elt = self.parse_compare(depth)?;
                elts.push(elt);
                if elts.len() > MAX_COLLECTION_LENGTH + 1 {
                    return Err(());
                }
            }
            if let Some(PyTok {
                kind: PyTokKind::RBrace,
                end,
                ..
            }) = self.peek()
            {
                let end_pos = *end;
                self.next_tok();
                Ok(PyAstNode {
                    kind: PyAstKind::Set(elts),
                    start,
                    end: end_pos,
                })
            } else {
                Err(())
            }
        }
    }
}

fn parse_py_eval(expr: &str) -> Result<PyAstNode, ()> {
    let tokens = tokenize_py_expr(expr)?;
    if tokens.is_empty() {
        return Err(());
    }
    let mut parser = PyParser::new(&tokens);
    parser.parse_eval_expr()
}

fn is_exact_2dp_float(val: f64) -> bool {
    if !val.is_finite() {
        return false;
    }
    match format!("{:.2}", val).parse::<f64>() {
        Ok(rounded) => rounded == val,
        Err(_) => false,
    }
}

fn is_safe_literal_ast(
    node: &PyAstNode,
    allowed_vars: Option<&BTreeSet<String>>,
    allow_inexact_floats: bool,
    depth: usize,
) -> bool {
    if depth > MAX_RECURSION_DEPTH {
        return false;
    }
    match &node.kind {
        PyAstKind::Bool | PyAstKind::None | PyAstKind::Bytes => true,
        PyAstKind::Str(s) => !s.contains('\0'),
        PyAstKind::Int(v) => *v <= (i64::MAX as u64),
        PyAstKind::OutOfRangeInt => false,
        PyAstKind::Float(f) => {
            if !f.is_finite() {
                return false;
            }
            if !allow_inexact_floats && !is_exact_2dp_float(*f) {
                return false;
            }
            true
        }
        PyAstKind::Unary { is_neg, operand } => match &operand.kind {
            PyAstKind::Int(v) => {
                if *is_neg {
                    *v <= (i64::MAX as u64) + 1
                } else {
                    *v <= (i64::MAX as u64)
                }
            }
            PyAstKind::OutOfRangeInt => false,
            PyAstKind::Float(f) => {
                if !f.is_finite() {
                    return false;
                }
                if !allow_inexact_floats && !is_exact_2dp_float(*f) {
                    return false;
                }
                true
            }
            _ => false,
        },
        PyAstKind::Call {
            func,
            args,
            keywords,
        } => {
            if func == "float" && args.len() == 1 && keywords.is_empty() {
                if let Some(PyAstNode {
                    kind: PyAstKind::Str(s),
                    ..
                }) = args.first()
                {
                    return matches!(s.as_str(), "inf" | "-inf" | "+inf");
                }
            }
            false
        }
        PyAstKind::List(elts) | PyAstKind::Tuple(elts) | PyAstKind::Set(elts) => {
            if elts.len() > MAX_COLLECTION_LENGTH {
                return false;
            }
            elts.iter()
                .all(|e| is_safe_literal_ast(e, allowed_vars, allow_inexact_floats, depth + 1))
        }
        PyAstKind::Dict(pairs) => {
            if pairs.len() > MAX_COLLECTION_LENGTH {
                return false;
            }
            pairs.iter().all(|(k, v)| {
                is_safe_literal_ast(k, allowed_vars, allow_inexact_floats, depth + 1)
                    && is_safe_literal_ast(v, allowed_vars, allow_inexact_floats, depth + 1)
            })
        }
        PyAstKind::Name(name) => allowed_vars.is_some_and(|vars| vars.contains(name)),
        PyAstKind::Compare { .. } => false,
    }
}

fn is_numeric_literal_ast(
    node: &PyAstNode,
    allowed_vars: Option<&BTreeSet<String>>,
) -> bool {
    match &node.kind {
        PyAstKind::Int(v) => *v <= (i64::MAX as u64),
        PyAstKind::Float(f) => f.is_finite(),
        PyAstKind::Unary { is_neg, operand } => match &operand.kind {
            PyAstKind::Int(v) => {
                if *is_neg {
                    *v <= (i64::MAX as u64) + 1
                } else {
                    *v <= (i64::MAX as u64)
                }
            }
            PyAstKind::Float(f) => f.is_finite(),
            _ => false,
        },
        PyAstKind::Name(name) => allowed_vars.is_some_and(|vars| vars.contains(name)),
        _ => false,
    }
}

fn is_safe_entry_call_ast(
    node: &PyAstNode,
    entry_point: &str,
    allowed_vars: &BTreeSet<String>,
) -> bool {
    if entry_point.is_empty()
        || entry_point.starts_with('_')
        || is_forbidden_example_name(entry_point)
    {
        return false;
    }
    match &node.kind {
        PyAstKind::Call {
            func,
            args,
            keywords,
        } if func == entry_point => {
            if args.len() > MAX_COLLECTION_LENGTH || keywords.len() > MAX_COLLECTION_LENGTH {
                return false;
            }
            args.iter()
                .all(|a| is_safe_literal_ast(a, Some(allowed_vars), true, 0))
                && keywords
                    .iter()
                    .all(|(_, v)| is_safe_literal_ast(v, Some(allowed_vars), true, 0))
        }
        _ => false,
    }
}

fn is_scalar_float_ast(node: &PyAstNode) -> bool {
    match &node.kind {
        PyAstKind::Float(_) => true,
        PyAstKind::Unary { operand, .. } => matches!(operand.kind, PyAstKind::Float(_)),
        _ => false,
    }
}

fn strip_outer_parens(mut s: &str) -> &str {
    loop {
        let trimmed = s.trim();
        if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
            return trimmed;
        }
        let bytes = trimmed.as_bytes();
        let mut depth = 0;
        let mut closes_at_end = false;
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escaped = false;
        let mut has_top_level_comma = false;
        for (i, &b) in bytes.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' && (in_single_quote || in_double_quote) {
                escaped = true;
                continue;
            }
            if in_single_quote {
                if b == b'\'' {
                    in_single_quote = false;
                }
                continue;
            }
            if in_double_quote {
                if b == b'"' {
                    in_double_quote = false;
                }
                continue;
            }
            match b {
                b'\'' => in_single_quote = true,
                b'"' => in_double_quote = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        if i == bytes.len() - 1 {
                            closes_at_end = true;
                        }
                        break;
                    }
                }
                b',' if depth == 1 => {
                    has_top_level_comma = true;
                }
                _ => {}
            }
        }
        if closes_at_end && !has_top_level_comma {
            if let Some(inner) = trimmed.get(1..trimmed.len() - 1) {
                s = inner;
            } else {
                return trimmed;
            }
        } else {
            return trimmed;
        }
    }
}

/// Deterministically extracts canonical example statements and assertions from a task prompt's
/// `Example:` or `Examples:` docstring section (ADR-011 H1).
pub fn extract_example_assertions(prompt: &str, entry_point: Option<&str>) -> Vec<String> {
    if prompt.is_empty() || prompt.len() > MAX_VERDICT_STREAM_BYTES {
        return Vec::new();
    }
    if !prompt.contains("Example:") && !prompt.contains("Examples:") {
        return Vec::new();
    }

    let marker = if prompt.contains("Example:") {
        "Example:"
    } else {
        "Examples:"
    };
    let Some((_, section)) = prompt.split_once(marker) else {
        return Vec::new();
    };

    let ep_owned: Option<String> = match entry_point {
        Some(s) if !s.is_empty() => Some(s.to_string()),
        _ => infer_entry_point(prompt, section),
    };
    let Some(ep) = ep_owned else {
        return Vec::new();
    };
    if ep.is_empty()
        || ep.starts_with('_')
        || is_forbidden_example_name(&ep)
        || !is_valid_identifier(&ep)
    {
        return Vec::new();
    }

    let lines = python_splitlines(section);
    let mut example_lines: Vec<&str> = Vec::new();
    for line in lines {
        let stripped = python_strip(line);
        if stripped.is_empty() {
            continue;
        }
        if !line.starts_with(' ')
            && !line.starts_with('\t')
            && !example_lines.is_empty()
            && stripped.contains(':')
        {
            break;
        }
        example_lines.push(stripped);
    }

    let mut blocks: Vec<String> = Vec::new();
    let mut current_block: Vec<&str> = Vec::new();
    for line in example_lines {
        if !current_block.is_empty() {
            let joined = current_block.join(" ");
            let (code_part, _) = split_code_and_comment(&joined);
            let open_parens =
                (code_part.matches('(').count() as isize) - (code_part.matches(')').count() as isize);
            let open_brackets =
                (code_part.matches('[').count() as isize) - (code_part.matches(']').count() as isize);
            let open_braces =
                (code_part.matches('{').count() as isize) - (code_part.matches('}').count() as isize);
            if open_parens <= 0 && open_brackets <= 0 && open_braces <= 0 {
                blocks.push(joined);
                current_block.clear();
                current_block.push(line);
                continue;
            }
        }
        current_block.push(line);
    }
    if !current_block.is_empty() {
        blocks.push(current_block.join(" "));
    }

    let mut statements: Vec<String> = Vec::new();
    let mut allowed_vars: BTreeSet<String> = BTreeSet::new();

    for blk in &blocks {
        if statements.len() >= MAX_EXTRACTED_STATEMENTS {
            break;
        }

        let (mut clean_blk, comment_part) = split_code_and_comment(blk);
        if clean_blk.is_empty() {
            continue;
        }
        if !comment_part.is_empty() && has_approx_marker(&comment_part) {
            continue;
        }
        let mut trimmed = clean_blk.trim_end();
        while let Some(stripped) = trimmed.strip_suffix(',') {
            trimmed = stripped.trim_end();
        }
        clean_blk = trimmed.to_string();
        if clean_blk.is_empty() {
            continue;
        }
        if clean_blk.contains('\0') || clean_blk.contains(r"\N{") {
            continue;
        }
        if clean_blk.chars().any(|c| (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r') {
            continue;
        }

        // Pattern 1: Arrow assertion `expr -> expected`
        if let Some((raw_expr, raw_expected)) = clean_blk.split_once("->") {
            let expr = python_strip(raw_expr);
            let expected = python_strip(raw_expected);
            if let (Ok(expr_ast), Ok(expected_ast)) =
                (parse_py_eval(expr), parse_py_eval(expected))
            {
                if is_safe_entry_call_ast(&expr_ast, &ep, &allowed_vars)
                    && is_safe_literal_ast(&expected_ast, None, false, 0)
                {
                    if is_scalar_float_ast(&expected_ast) {
                        statements.push(format!(
                            "assert isinstance(({}), (int, float)) and not isinstance(({}), bool) and abs(({}) - ({})) <= 1e-3",
                            expr, expr, expr, expected
                        ));
                    } else {
                        statements.push(format!("assert {} == {}", expr, expected));
                    }
                    continue;
                }
            }
            continue;
        }

        // Pattern 2: Direct comparison assertion
        if [">", "<", ">=", "<=", "=="]
            .iter()
            .any(|op| clean_blk.contains(op))
            && clean_blk.contains(&ep)
        {
            if let Ok(PyAstNode {
                kind: PyAstKind::Compare { left, op, right },
                ..
            }) = parse_py_eval(&clean_blk)
            {
                let has_entry_call = is_safe_entry_call_ast(&left, &ep, &allowed_vars)
                    || is_safe_entry_call_ast(&right, &ep, &allowed_vars);
                if has_entry_call {
                    match op {
                        PyCmpOp::Gt | PyCmpOp::Lt | PyCmpOp::GtE | PyCmpOp::LtE => {
                            let left_is_call = is_safe_entry_call_ast(&left, &ep, &allowed_vars);
                            let right_is_call = is_safe_entry_call_ast(&right, &ep, &allowed_vars);
                            let left_ok = left_is_call || is_numeric_literal_ast(&left, Some(&allowed_vars));
                            let right_ok = right_is_call || is_numeric_literal_ast(&right, Some(&allowed_vars));
                            if left_ok && right_ok {
                                if let (Some(lhs), Some(rhs)) = (
                                    clean_blk.get(left.start..left.end),
                                    clean_blk.get(right.start..right.end),
                                ) {
                                    let clean_lhs = strip_outer_parens(lhs);
                                    let clean_rhs = strip_outer_parens(rhs);
                                    if !clean_lhs.is_empty() && !clean_rhs.is_empty() {
                                        statements.push(format!(
                                            "assert isinstance(({}), (int, float)) and not isinstance(({}), bool) and isinstance(({}), (int, float)) and not isinstance(({}), bool) and ({})",
                                            clean_lhs, clean_lhs, clean_rhs, clean_rhs, clean_blk
                                        ));
                                        continue;
                                    }
                                }
                            }
                        }
                        PyCmpOp::Eq => {
                            let left_ok = is_safe_entry_call_ast(&left, &ep, &allowed_vars)
                                || is_safe_literal_ast(&left, Some(&allowed_vars), false, 0);
                            let right_ok = is_safe_entry_call_ast(&right, &ep, &allowed_vars)
                                || is_safe_literal_ast(&right, Some(&allowed_vars), false, 0);
                            if left_ok && right_ok {
                                statements.push(format!("assert {}", clean_blk));
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // Pattern 3: Variable assignment `var = <safe_literal_or_container>`
        if clean_blk.contains('=') && !clean_blk.starts_with("assert") {
            if let Ok(tokens) = tokenize_py_expr(&clean_blk) {
                if tokens.len() >= 3 {
                    if let (
                        Some(PyTok {
                            kind: PyTokKind::Ident(var_name),
                            ..
                        }),
                        Some(PyTok {
                            kind: PyTokKind::Assign,
                            ..
                        }),
                    ) = (tokens.first(), tokens.get(1))
                    {
                        if !is_python_keyword(var_name)
                            && !var_name.starts_with('_')
                            && var_name != &ep
                            && !is_forbidden_example_name(var_name)
                        {
                            if let Some(rhs_tokens) = tokens.get(2..) {
                                let mut rhs_parser = PyParser::new(rhs_tokens);
                                if let Ok(rhs_ast) = rhs_parser.parse_eval_expr() {
                                    if is_safe_literal_ast(&rhs_ast, Some(&allowed_vars), false, 0)
                                    {
                                        allowed_vars.insert(var_name.clone());
                                        statements.push(clean_blk);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !statements.iter().any(|s| s.starts_with("assert ")) {
        return Vec::new();
    }
    statements
}

// ============================================================================
// 8. Unit Tests & Deterministic No-Panic Property Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_and_hmac_sha256_vectors() {
        // Empty string SHA-256
        let empty_digest = hex_encode(&sha256(b""));
        assert_eq!(
            empty_digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // "abc" SHA-256
        let abc_digest = hex_encode(&sha256(b"abc"));
        assert_eq!(
            abc_digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // RFC 4231 Test Case 2 for HMAC-SHA256
        let mac = hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?"));
        assert_eq!(
            mac,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(constant_time_eq(mac.as_bytes(), mac.as_bytes()));
        assert!(!constant_time_eq(mac.as_bytes(), b"different"));
    }

    #[test]
    fn test_codec_policy_and_roundtrip() {
        let policy = get_codec_policy();
        assert_eq!(policy.max_recursion_depth, 32);
        assert_eq!(policy.max_collection_length, 1000);
        assert_eq!(policy.max_item_count, 50000);
        assert_eq!(policy.min_int64, i64::MIN);
        assert_eq!(policy.max_int64, i64::MAX);

        // Reject duplicate set elements including Python numeric equivalence (1, True, 1.0)
        let dup_set = decode_envelope_json(
            r#"{"t":"set","v":[{"t":"int","v":1},{"t":"bool","v":true}]}"#,
        );
        assert!(dup_set.is_err());

        // Reject duplicate JSON object keys in raw envelope
        let dup_json_keys = decode_envelope_json(r#"{"t":"int","t":"int","v":42}"#);
        assert!(dup_json_keys.is_err());

        // Reject float token for int tag
        let float_for_int = decode_envelope_json(r#"{"t":"int","v":42.0}"#);
        assert!(float_for_int.is_err());
    }

    #[test]
    fn test_verdict_frame_reversed_markers_and_duplicate_keys_rejected() {
        let reversed = "---PAI_VERDICT_END---\n{\"status\": \"PASS\"}\n---PAI_VERDICT_START---";
        let res = verify_verdict_frame(reversed, "nonce", "key", &[], 0, "ok", None);
        assert!(!res.passed);
        assert_eq!(res.status, "INTEGRITY_VIOLATION");
        assert_eq!(res.error_type.as_deref(), Some("VerdictParseError"));

        let dup_key_frame = "\n---PAI_VERDICT_START---\n{\"status\": \"FAIL\", \"status\": \"PASS\"}\n---PAI_VERDICT_END---\n";
        let res2 = verify_verdict_frame(dup_key_frame, "nonce", "key", &[], 0, "ok", None);
        assert!(!res2.passed);
        assert_eq!(res2.status, "INTEGRITY_VIOLATION");
        assert_eq!(res2.error_type.as_deref(), Some("VerdictParseError"));
    }

    #[test]
    fn test_no_panic_random_bytes_and_json_property() {
        // Deterministic XorShift64 PRNG across 5,000 hostile/random byte sequences,
        // arbitrary multibyte UTF-8 strings (Sinhala, ZWJ, control chars, surrogates),
        // and mutated JSON / verdict frames.
        struct XorShift64(u64);
        impl XorShift64 {
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn next_usize(&mut self, bound: usize) -> usize {
                if bound == 0 {
                    0
                } else {
                    (self.next_u64() as usize) % bound
                }
            }
        }

        let mut rng = XorShift64(0x2026_1012_dead_beef);
        let alphabet: &[&str] = &[
            "{", "}", "[", "]", "\"", ":", ",", "t", "v", "int", "float", "str", "bytes",
            "list", "tuple", "set", "frozenset", "dict", "none", "bool", "true", "false",
            "null", "nan", "inf", "-inf", "0", "-1", "9223372036854775807",
            "-9223372036854775808", "9223372036854775808", "-9223372036854775809",
            "1e500", "\\u0000", "\\ud800", "\\ud83d\\ude00", "සිංහල", "ක්\u{200d}ර",
            "---PAI_VERDICT_START---", "---PAI_VERDICT_END---", "Example:", "Examples:",
            "->", "==", ">=", "<=", "=", "(", ")", "#", "~", "approx", "\n", "\r\n", "\x00",
        ];

        for _ in 0..5_000 {
            let token_count = rng.next_usize(36);
            let mut s = String::new();
            for _ in 0..token_count {
                let piece = alphabet[rng.next_usize(alphabet.len())];
                s.push_str(piece);
            }

            // 1. Codec JSON parser & decoder must never panic
            let _ = decode_envelope_json(&s);

            // 2. Verdict frame verifier must never panic
            let _ = verify_verdict_frame(
                &s,
                "0123456789abcdef",
                "fedcba9876543210",
                &["test_a".to_string()],
                0,
                "ok",
                Some("aaaa"),
            );

            // 3. Canonical example extractor must never panic
            let _ = extract_example_assertions(&s, None);
            let _ = extract_example_assertions(&s, Some("solve"));

            // 4. Random raw byte buffer converted via lossy UTF-8 must never panic
            let raw_len = rng.next_usize(128);
            let mut raw_bytes = Vec::with_capacity(raw_len);
            for _ in 0..raw_len {
                raw_bytes.push((rng.next_u64() & 0xff) as u8);
            }
            let lossy = String::from_utf8_lossy(&raw_bytes);
            let _ = decode_envelope_json(&lossy);
            let _ = verify_verdict_frame(&lossy, "n", "k", &[], 1, "timeout", None);
            let _ = extract_example_assertions(&lossy, None);
        }
    }

    #[test]
    fn test_format_python_float_parity() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (-1.0, "-1.0"),
            (1.5, "1.5"),
            (-1.5, "-1.5"),
            (1e-4, "0.0001"),
            (-1e-4, "-0.0001"),
            (1e-5, "1e-05"),
            (-1e-5, "-1e-05"),
            (1.25e-5, "1.25e-05"),
            (-1.25e-5, "-1.25e-05"),
            (1e15, "1000000000000000.0"),
            (-1e15, "-1000000000000000.0"),
            (1e16, "1e+16"),
            (-1e16, "-1e+16"),
            (1.25e16, "1.25e+16"),
            (-1.25e16, "-1.25e+16"),
            (1e22, "1e+22"),
            (-1e22, "-1e+22"),
            (5e-324, "5e-324"),
            (-5e-324, "-5e-324"),
            (1.7976931348623157e+308, "1.7976931348623157e+308"),
            (2.2250738585072014e-308, "2.2250738585072014e-308"),
        ];
        for &(v, expected) in cases {
            let got = format_python_float(v);
            assert_eq!(got, expected, "Mismatch for {}", v);
        }
    }

    #[test]
    fn test_paren_neg_assertion_parity() {
        let prompt = "Example:\n  solve(1) > -(1)";
        let stmts = extract_example_assertions(prompt, Some("solve"));
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0],
            "assert isinstance((solve(1)), (int, float)) and not isinstance((solve(1)), bool) and isinstance((-(1)), (int, float)) and not isinstance((-(1)), bool) and (solve(1) > -(1))"
        );
    }

    #[test]
    fn test_trailing_comma_assertion_parity() {
        let prompt = "Example:\n  solve(1) -> 1,\n  solve(2) -> 2 ,";
        let stmts = extract_example_assertions(prompt, Some("solve"));
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0], "assert solve(1) == 1");
        assert_eq!(stmts[1], "assert solve(2) == 2");
    }

    #[test]
    fn test_rb_bytes_literal() {
        let prompt = "Example:\n  solve(rb'x') -> 1";
        let stmts = extract_example_assertions(prompt, Some("solve"));
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0], "assert solve(rb'x') == 1");
    }

    #[test]
    fn test_sinhala_entry_point() {
        let prompt = "def සිංහල(n):\nExample:\n  සිංහල(1) -> 2";
        let stmts = extract_example_assertions(prompt, None);
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0], "assert සිංහල(1) == 2");
    }

    #[test]
    fn test_max_extracted_statements_cap() {
        let mut prompt = String::from("Example:\n");
        for i in 0..70 {
            prompt.push_str(&format!("  solve({}) -> {}\n", i, i));
        }
        let stmts = extract_example_assertions(&prompt, Some("solve"));
        assert_eq!(stmts.len(), MAX_EXTRACTED_STATEMENTS);
    }

    #[test]
    fn test_greater_than_paren_rhs() {
        let prompt = "Example:\n  solve(1) > (1)";
        let stmts = extract_example_assertions(prompt, Some("solve"));
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0],
            "assert isinstance((solve(1)), (int, float)) and not isinstance((solve(1)), bool) and isinstance((1), (int, float)) and not isinstance((1), bool) and (solve(1) > (1))"
        );
    }

    #[test]
    fn test_rejected_string_escapes_and_nul() {
        // Truncated \x
        let p1 = "Example:\n  solve('\\x4') -> 1";
        assert!(extract_example_assertions(p1, Some("solve")).is_empty());

        // Out-of-range \U
        let p2 = "Example:\n  solve('\\U00110000') -> 1";
        assert!(extract_example_assertions(p2, Some("solve")).is_empty());

        // Named escape \N
        let p3 = "Example:\n  solve('\\N{SPACE}') -> 1";
        assert!(extract_example_assertions(p3, Some("solve")).is_empty());

        // Escaped \0 and \x00
        let p4 = "Example:\n  solve('\\0') -> 1";
        assert!(extract_example_assertions(p4, Some("solve")).is_empty());
        let p5 = "Example:\n  solve('\\x00') -> 1";
        assert!(extract_example_assertions(p5, Some("solve")).is_empty());

        // Raw control character (e.g. \x01)
        let p6 = "Example:\n  solve('\x01') -> 1";
        assert!(extract_example_assertions(p6, Some("solve")).is_empty());
    }

    #[test]
    fn test_rejected_fullwidth_and_compat_identifiers() {
        // Fullwidth open
        let p1 = "def \u{ff4f}pen(n):\nExample:\n  \u{ff4f}pen(1) -> 2";
        assert!(extract_example_assertions(p1, None).is_empty());

        // Fullwidth eval
        let p2 = "def \u{ff45}val(n):\nExample:\n  \u{ff45}val(1) -> 2";
        assert!(extract_example_assertions(p2, None).is_empty());

        // Superscript squared in identifier
        let p3 = "def solve\u{00b2}(n):\nExample:\n  solve\u{00b2}(1) -> 2";
        assert!(extract_example_assertions(p3, None).is_empty());
    }

    #[test]
    fn test_streaming_sha256_hasher_matches_oneshot() {
        let payloads: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            &[42u8; 55],
            &[42u8; 56],
            &[42u8; 64],
            &[42u8; 65],
            &[42u8; 119],
            &[42u8; 120],
            &[42u8; 128],
            &[42u8; 1000],
        ];

        for payload in payloads {
            let oneshot = sha256(payload);

            for chunk_size in [1, 2, 7, 16, 55, 64, 100] {
                let mut hasher = Sha256Hasher::new();
                for chunk in payload.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                let streamed = hasher.finalize();
                assert_eq!(
                    streamed, oneshot,
                    "Streaming SHA-256 with chunk size {} differed from oneshot for payload len {}",
                    chunk_size,
                    payload.len()
                );
            }
        }
    }
}




