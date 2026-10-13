//! Slice 3: Inter-Process Communication (IPC) Bridge for `pai-core`.
//!
//! Provides a stateless JSON-in/JSON-out bridge accessible via `--bridge` and `--json-bridge`.
//! Reads requests from stdin and writes responses to stdout.
//! Enforces:
//! - 16 MiB request size cap (fail-closed before parsing)
//! - Strict JSON parse rejecting duplicate object keys and unbounded nesting
//! - Strongly-typed schemas with `#[serde(deny_unknown_fields)]` rejecting unknown fields
//! - Mandatory fields on security primitives (no permissive defaulting)
//! - Numeric range checks (e.g. positive bounded `max_line_length`)

#![deny(unsafe_code)]

use std::io::{self, Read};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ed25519;
use crate::ingest::{
    defang_envelope_markers, get_ingest_limits, is_junk_dir, is_secret_file,
    sanitize_header, sanitize_terminal_output, sanitize_text_content, scan_secret_content,
    wrap_untrusted_envelope,
};
use crate::updater::{self, TrustConfig};
use crate::verify_loop::{
    decode_envelope_json, decode_value, encode_value, extract_example_assertions,
    parse_strict_json, verify_verdict_frame,
};

pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
}

impl BridgeResponse {
    pub fn ok(result: Value) -> Self {
        Self {
            status: "ok".into(),
            result: Some(result),
            error: None,
            error_type: None,
        }
    }

    pub fn err(err_msg: impl Into<String>, err_type: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            result: None,
            error: Some(err_msg.into()),
            error_type: Some(err_type.into()),
        }
    }
}

fn default_max_line_length() -> usize {
    4000
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
#[serde(deny_unknown_fields)]
pub enum BridgeRequest {
    #[serde(rename = "handshake")]
    Handshake {},

    #[serde(rename = "get_ingest_limits")]
    GetIngestLimits {},

    #[serde(rename = "is_secret_file")]
    IsSecretFile {
        path: String,
    },

    #[serde(rename = "is_junk_dir")]
    IsJunkDir {
        dirname: String,
    },

    #[serde(rename = "scan_secret_content")]
    ScanSecretContent {
        text: String,
        #[serde(default)]
        file_path: Option<String>,
    },

    #[serde(rename = "sanitize_terminal_output")]
    SanitizeTerminalOutput {
        text: String,
    },

    #[serde(rename = "sanitize_text_content")]
    SanitizeTextContent {
        text: String,
        #[serde(default = "default_max_line_length")]
        max_line_length: usize,
    },

    #[serde(rename = "sanitize_header")]
    SanitizeHeader {
        header: String,
    },

    #[serde(rename = "defang_envelope_markers")]
    DefangEnvelopeMarkers {
        text: String,
        #[serde(default)]
        nonce: Option<String>,
    },

    #[serde(rename = "wrap_untrusted_envelope")]
    WrapUntrustedEnvelope {
        #[serde(alias = "text")]
        content: String,
        #[serde(default)]
        header: Option<String>,
        nonce: String,
    },

    #[serde(rename = "decode_envelope_json")]
    DecodeEnvelopeJson {
        raw_json: String,
    },

    #[serde(rename = "decode_value")]
    DecodeValue {
        envelope: Value,
    },

    #[serde(rename = "verify_verdict_frame")]
    VerifyVerdictFrame {
        comb_out: String,
        parent_nonce: String,
        parent_hmac_key: String,
        #[serde(default)]
        expected_test_ids: Vec<String>,
        exit_code: i32,
        res_status: String,
        #[serde(default)]
        expected_test_hash: Option<String>,
    },

    #[serde(rename = "extract_example_assertions")]
    ExtractExampleAssertions {
        prompt: String,
        #[serde(default)]
        entry_point: Option<String>,
    },

    #[serde(rename = "verify_ed25519")]
    VerifyEd25519 {
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    },

    #[serde(rename = "verify_release")]
    VerifyRelease {
        release_dir: String,
        trust_root_json: String,
        expected_product: String,
        #[serde(default)]
        check_rollback: bool,
        #[serde(default)]
        highest_seen_version: Option<String>,
    },
}

pub fn handle_typed_bridge_request(req: BridgeRequest) -> BridgeResponse {
    match req {
        BridgeRequest::Handshake {} => {
            let data = serde_json::json!({
                "crate_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": 1,
                "platform": std::env::consts::OS,
                "conformance_vector_count": 92,
                "conformance_vectors_hash": env!("PAI_CONFORMANCE_VECTORS_HASH"),
            });
            BridgeResponse::ok(data)
        }

        BridgeRequest::GetIngestLimits {} => match serde_json::to_value(get_ingest_limits()) {
            Ok(v) => BridgeResponse::ok(v),
            Err(e) => BridgeResponse::err(format!("Serialization error: {}", e), "SerializationError"),
        },

        BridgeRequest::IsSecretFile { path } => {
            BridgeResponse::ok(Value::Bool(is_secret_file(&path)))
        }

        BridgeRequest::IsJunkDir { dirname } => {
            BridgeResponse::ok(Value::Bool(is_junk_dir(&dirname)))
        }

        BridgeRequest::ScanSecretContent { text, file_path } => {
            match scan_secret_content(&text, file_path.as_deref()) {
                Some(secret_type) => BridgeResponse::ok(Value::String(secret_type.to_string())),
                None => BridgeResponse::ok(Value::Null),
            }
        }

        BridgeRequest::SanitizeTerminalOutput { text } => {
            BridgeResponse::ok(Value::String(sanitize_terminal_output(&text)))
        }

        BridgeRequest::SanitizeTextContent { text, max_line_length } => {
            if max_line_length == 0 || max_line_length > 1_000_000 {
                return BridgeResponse::err(
                    "max_line_length must be between 1 and 1000000",
                    "InvalidParameter",
                );
            }
            BridgeResponse::ok(Value::String(sanitize_text_content(&text, max_line_length)))
        }

        BridgeRequest::SanitizeHeader { header } => {
            BridgeResponse::ok(Value::String(sanitize_header(&header)))
        }

        BridgeRequest::DefangEnvelopeMarkers { text, nonce } => {
            BridgeResponse::ok(Value::String(defang_envelope_markers(&text, nonce.as_deref())))
        }

        BridgeRequest::WrapUntrustedEnvelope { content, header, nonce } => {
            BridgeResponse::ok(Value::String(wrap_untrusted_envelope(
                &content,
                header.as_deref(),
                &nonce,
            )))
        }

        BridgeRequest::DecodeEnvelopeJson { raw_json } => match decode_envelope_json(&raw_json) {
            Ok(pai_val) => match encode_value(&pai_val) {
                Ok(enc_val) => BridgeResponse::ok(enc_val),
                Err(e) => BridgeResponse::err(format!("{}", e), "CodecError"),
            },
            Err(e) => BridgeResponse::err(format!("{}", e), "CodecError"),
        },

        BridgeRequest::DecodeValue { envelope } => match decode_value(&envelope) {
            Ok(pai_val) => match encode_value(&pai_val) {
                Ok(enc_val) => BridgeResponse::ok(enc_val),
                Err(e) => BridgeResponse::err(format!("{}", e), "CodecError"),
            },
            Err(e) => BridgeResponse::err(format!("{}", e), "CodecError"),
        },

        BridgeRequest::VerifyVerdictFrame {
            comb_out,
            parent_nonce,
            parent_hmac_key,
            expected_test_ids,
            exit_code,
            res_status,
            expected_test_hash,
        } => {
            let res = verify_verdict_frame(
                &comb_out,
                &parent_nonce,
                &parent_hmac_key,
                &expected_test_ids,
                exit_code,
                &res_status,
                expected_test_hash.as_deref(),
            );
            match serde_json::to_value(&res) {
                Ok(v) => BridgeResponse::ok(v),
                Err(e) => BridgeResponse::err(format!("Serialization error: {}", e), "SerializationError"),
            }
        }

        BridgeRequest::ExtractExampleAssertions { prompt, entry_point } => {
            let stmts = extract_example_assertions(&prompt, entry_point.as_deref());
            match serde_json::to_value(&stmts) {
                Ok(v) => BridgeResponse::ok(v),
                Err(e) => BridgeResponse::err(format!("Serialization error: {}", e), "SerializationError"),
            }
        }

        BridgeRequest::VerifyEd25519 {
            public_key_hex,
            message_hex,
            signature_hex,
        } => {
            let pk_clean = public_key_hex.trim();
            let sig_clean = signature_hex.trim();
            let msg_clean = message_hex.trim();

            if pk_clean.len() != 64 || sig_clean.len() != 128 || !msg_clean.len().is_multiple_of(2) {
                return BridgeResponse::ok(Value::Bool(false));
            }

            let mut pk = [0u8; 32];
            for i in 0..32 {
                match u8::from_str_radix(&pk_clean[i * 2..i * 2 + 2], 16) {
                    Ok(b) => pk[i] = b,
                    Err(_) => return BridgeResponse::ok(Value::Bool(false)),
                }
            }

            let mut sig = [0u8; 64];
            for i in 0..64 {
                match u8::from_str_radix(&sig_clean[i * 2..i * 2 + 2], 16) {
                    Ok(b) => sig[i] = b,
                    Err(_) => return BridgeResponse::ok(Value::Bool(false)),
                }
            }

            let mut msg = Vec::with_capacity(msg_clean.len() / 2);
            for i in 0..msg_clean.len() / 2 {
                match u8::from_str_radix(&msg_clean[i * 2..i * 2 + 2], 16) {
                    Ok(b) => msg.push(b),
                    Err(_) => return BridgeResponse::ok(Value::Bool(false)),
                }
            }

            let valid = ed25519::verify(&pk, &msg, &sig);
            BridgeResponse::ok(Value::Bool(valid))
        }

        BridgeRequest::VerifyRelease {
            release_dir,
            trust_root_json,
            expected_product,
            check_rollback,
            highest_seen_version,
        } => {
            let trust_config: TrustConfig = match serde_json::from_str(&trust_root_json) {
                Ok(c) => c,
                Err(e) => return BridgeResponse::err(format!("Invalid trust configuration: {}", e), "InvalidTrustConfig"),
            };

            match updater::verify_release(
                std::path::Path::new(&release_dir),
                &trust_config,
                &expected_product,
                check_rollback,
                highest_seen_version.as_deref(),
            ) {
                Ok(verified) => match serde_json::to_value(&verified) {
                    Ok(v) => BridgeResponse::ok(v),
                    Err(e) => BridgeResponse::err(format!("Serialization error: {}", e), "SerializationError"),
                },
                Err(e) => BridgeResponse::err(e.0, "UpdateRejected"),
            }
        }
    }
}

pub fn handle_raw_bridge_request(raw_json: &str) -> BridgeResponse {
    let strict_parsed = match parse_strict_json(
        raw_json,
        MAX_REQUEST_BYTES,
        64,
        100_000,
        None,
        true,
    ) {
        Ok(sj) => sj,
        Err(err) => {
            return BridgeResponse::err(
                format!("Invalid request JSON: {}", err),
                "JsonParseError",
            );
        }
    };

    let value = match strict_parsed.to_serde_value() {
        Ok(v) => v,
        Err(err) => {
            return BridgeResponse::err(
                format!("JSON conversion error: {}", err),
                "JsonParseError",
            );
        }
    };

    let req: BridgeRequest = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(err) => {
            return BridgeResponse::err(
                format!("Invalid request schema: {}", err),
                "InvalidRequest",
            );
        }
    };

    handle_typed_bridge_request(req)
}

pub fn run_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut input_bytes = Vec::new();
    stdin_lock
        .by_ref()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input_bytes)?;

    if input_bytes.len() > MAX_REQUEST_BYTES {
        let resp = BridgeResponse::err(
            "Request input exceeds maximum limit of 16 MiB",
            "RequestTooLarge",
        );
        println!("{}", serde_json::to_string(&resp)?);
        return Ok(());
    }

    let input_str = match std::str::from_utf8(&input_bytes) {
        Ok(s) => s.trim(),
        Err(e) => {
            let resp = BridgeResponse::err(
                format!("Request input is not valid UTF-8: {}", e),
                "InvalidEncoding",
            );
            println!("{}", serde_json::to_string(&resp)?);
            return Ok(());
        }
    };

    if input_str.is_empty() {
        return Ok(());
    }

    if input_str.starts_with('{') {
        let resp = handle_raw_bridge_request(input_str);
        println!("{}", serde_json::to_string(&resp)?);
        return Ok(());
    }

    for line in input_str.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let resp = handle_raw_bridge_request(l);
        println!("{}", serde_json::to_string(&resp)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_handshake() {
        let req = r#"{"op": "handshake"}"#;
        let resp = handle_raw_bridge_request(req);
        assert_eq!(resp.status, "ok");
        let res = resp.result.expect("result must be present");
        assert_eq!(res["protocol_version"], 1);
        assert_eq!(res["crate_version"], "0.1.0");
        assert_eq!(res["conformance_vector_count"], 92);
        assert_eq!(res["conformance_vectors_hash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn test_bridge_duplicate_keys_rejected() {
        let req = r#"{"op": "is_secret_file", "path": ".env", "path": "other"}"#;
        let resp = handle_raw_bridge_request(req);
        assert_eq!(resp.status, "error");
        assert_eq!(resp.error_type, Some("JsonParseError".to_string()));
        assert!(resp.error.unwrap().contains("Duplicate key"));
    }

    #[test]
    fn test_bridge_unknown_fields_rejected() {
        let req = r#"{"op": "is_secret_file", "path": ".env", "extra_bogus_field": true}"#;
        let resp = handle_raw_bridge_request(req);
        assert_eq!(resp.status, "error");
        assert_eq!(resp.error_type, Some("InvalidRequest".to_string()));
        assert!(resp.error.unwrap().contains("unknown field `extra_bogus_field`"));
    }

    #[test]
    fn test_bridge_missing_required_fields_rejected() {
        let req = r#"{"op": "verify_verdict_frame", "comb_out": "test"}"#;
        let resp = handle_raw_bridge_request(req);
        assert_eq!(resp.status, "error");
        assert_eq!(resp.error_type, Some("InvalidRequest".to_string()));
        assert!(resp.error.unwrap().contains("missing field"));
    }

    #[test]
    fn test_bridge_string_exit_code_rejected() {
        let req = r#"{
            "op": "verify_verdict_frame",
            "comb_out": "test",
            "parent_nonce": "nonce123",
            "parent_hmac_key": "key123",
            "exit_code": "0",
            "res_status": "ok"
        }"#;
        let resp = handle_raw_bridge_request(req);
        assert_eq!(resp.status, "error");
        assert_eq!(resp.error_type, Some("InvalidRequest".to_string()));
        assert!(resp.error.unwrap().contains("invalid type: string"));
    }

    #[test]
    fn test_bridge_typo_runner_status_rejected() {
        let req = r#"{
            "op": "verify_verdict_frame",
            "comb_out": "test",
            "parent_nonce": "nonce123",
            "parent_hmac_key": "key123",
            "exit_code": 0,
            "runner_status": "ok"
        }"#;
        let resp = handle_raw_bridge_request(req);
        assert_eq!(resp.status, "error");
        assert_eq!(resp.error_type, Some("InvalidRequest".to_string()));
        assert!(resp.error.unwrap().contains("unknown field `runner_status`"));
    }

    #[test]
    fn test_bridge_max_line_length_bounds() {
        let req_zero = r#"{"op": "sanitize_text_content", "text": "hello", "max_line_length": 0}"#;
        let resp_zero = handle_raw_bridge_request(req_zero);
        assert_eq!(resp_zero.status, "error");
        assert_eq!(resp_zero.error_type, Some("InvalidParameter".to_string()));

        let req_neg = r#"{"op": "sanitize_text_content", "text": "hello", "max_line_length": -5}"#;
        let resp_neg = handle_raw_bridge_request(req_neg);
        assert_eq!(resp_neg.status, "error");
        assert_eq!(resp_neg.error_type, Some("InvalidRequest".to_string()));
    }
}
