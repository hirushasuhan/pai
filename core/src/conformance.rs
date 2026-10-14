//! Conformance vector runner (VS2, Phase 2 Slice 1 Safe Ingestion & Slice 2 Verify-Loop/Codec)
//! Reads golden vector files and validates that Rust implementations
//! match the Python specification with 0 discrepancies.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ingest::{
    defang_envelope_markers, get_ingest_limits, is_junk_dir, is_secret_file, sanitize_header,
    sanitize_terminal_output, sanitize_text_content, scan_secret_content, wrap_untrusted_envelope,
    IngestLimits,
};
use crate::tier::{calculate_budget, HardwareBudget, TierInput};
use crate::url_policy::evaluate_url;
use crate::verify_loop::{
    decode_envelope_json, decode_value, encode_value, encode_value_strict,
    extract_example_assertions, get_codec_policy, verify_verdict_frame, CodecPolicy,
    VerdictVerificationResult,
};

#[derive(Debug, Deserialize)]
pub struct TierVectorCase {
    pub input: TierInput,
    pub expected: HardwareBudget,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UrlVectorCase {
    pub url: String,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct SecretFileCase {
    pub path: String,
    pub expected: bool,
}

#[derive(Debug, Deserialize)]
pub struct JunkDirCase {
    pub dirname: String,
    pub expected: bool,
}

#[derive(Debug, Deserialize)]
pub struct SecretContentCase {
    pub id: String,
    pub file_path: Option<String>,
    pub text_parts: Vec<String>,
    pub expected: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SanitizeTerminalCase {
    pub id: String,
    pub input: String,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct SanitizeTextCase {
    pub id: String,
    pub raw_utf8: String,
    pub max_line_length: usize,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct SanitizeHeaderCase {
    pub id: String,
    pub header: String,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeCase {
    pub id: String,
    pub content: String,
    pub header: Option<String>,
    pub nonce: String,
    pub expected_defanged: String,
    pub expected_envelope: String,
}

#[derive(Debug, Deserialize)]
pub struct IngestVectorsFile {
    pub schema_version: u32,
    pub limits: IngestLimits,
    pub secret_file_cases: Vec<SecretFileCase>,
    pub junk_dir_cases: Vec<JunkDirCase>,
    pub secret_content_cases: Vec<SecretContentCase>,
    pub sanitize_terminal_cases: Vec<SanitizeTerminalCase>,
    pub sanitize_text_cases: Vec<SanitizeTextCase>,
    pub sanitize_header_cases: Vec<SanitizeHeaderCase>,
    pub envelope_cases: Vec<EnvelopeCase>,
}

#[derive(Debug, Deserialize)]
pub struct CodecRoundtripCase {
    pub id: String,
    pub python_type: String,
    pub encoded: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CodecInvalidEnvelopeCase {
    pub id: String,
    pub envelope: serde_json::Value,
    pub expected_error: String,
}

#[derive(Debug, Deserialize)]
pub struct CodecEnvelopeJsonDiffCase {
    pub id: String,
    pub raw_json: String,
    pub expected_ok: bool,
    pub expected_python_type: Option<String>,
    pub expected_re_encoded_json: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerdictFrameCase {
    pub id: String,
    pub stdout: String,
    pub parent_nonce: String,
    pub parent_hmac_key: String,
    pub expected_test_ids: Vec<String>,
    pub expected_test_hash: Option<String>,
    pub exit_code: i32,
    pub res_status: String,
    pub expected: VerdictVerificationResult,
}

#[derive(Debug, Deserialize)]
pub struct CanonicalExampleExtractionCase {
    pub id: String,
    pub entry_point: String,
    pub prompt: String,
    pub expected_statements: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyLoopVectorsFile {
    pub schema_version: u32,
    pub codec_policy: CodecPolicy,
    pub codec_roundtrip_cases: Vec<CodecRoundtripCase>,
    pub codec_invalid_envelope_cases: Vec<CodecInvalidEnvelopeCase>,
    pub verdict_frame_cases: Vec<VerdictFrameCase>,
    pub canonical_example_extraction_cases: Vec<CanonicalExampleExtractionCase>,
}

#[derive(Debug, Default, Deserialize)]
pub struct IngestDifferentialCases {
    #[serde(default)]
    pub secret_file_cases: Vec<SecretFileCase>,
    #[serde(default)]
    pub junk_dir_cases: Vec<JunkDirCase>,
    #[serde(default)]
    pub secret_content_cases: Vec<SecretContentCase>,
    #[serde(default)]
    pub sanitize_terminal_cases: Vec<SanitizeTerminalCase>,
    #[serde(default)]
    pub sanitize_text_cases: Vec<SanitizeTextCase>,
    #[serde(default)]
    pub sanitize_header_cases: Vec<SanitizeHeaderCase>,
    #[serde(default)]
    pub envelope_cases: Vec<EnvelopeCase>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VerifyLoopDifferentialCases {
    #[serde(default)]
    pub codec_roundtrip_cases: Vec<CodecRoundtripCase>,
    #[serde(default)]
    pub codec_invalid_envelope_cases: Vec<CodecInvalidEnvelopeCase>,
    #[serde(default)]
    pub codec_envelope_json_cases: Vec<CodecEnvelopeJsonDiffCase>,
    #[serde(default)]
    pub verdict_frame_cases: Vec<VerdictFrameCase>,
    #[serde(default)]
    pub example_extraction_cases: Vec<CanonicalExampleExtractionCase>,
}

#[derive(Debug, Deserialize)]
pub struct DifferentialDataset {
    pub tier_cases: Vec<TierVectorCase>,
    pub url_cases: Vec<UrlVectorCase>,
    #[serde(default)]
    pub ingest_cases: IngestDifferentialCases,
    #[serde(default)]
    pub verify_loop_cases: VerifyLoopDifferentialCases,
}

pub fn run_tier_conformance(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let cases: Vec<TierVectorCase> = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut failed = 0;
    for (idx, case) in cases.iter().enumerate() {
        let got = calculate_budget(
            case.input.avail_ram_mb,
            case.input.memory_load_pct,
            case.input.cpu_load_pct,
            case.input.battery.clone(),
            case.input.cpu_cores,
        );
        if got != case.expected {
            eprintln!(
                "TIER VECTOR MISMATCH at index {}:\n  Input: {:?}\n  Expected: {:?}\n  Actual:   {:?}",
                idx, case.input, case.expected, got
            );
            failed += 1;
        }
    }

    if failed > 0 {
        Err(format!("{} tier vectors failed", failed))
    } else {
        Ok(cases.len())
    }
}

pub fn run_url_conformance(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let cases: Vec<UrlVectorCase> = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut failed = 0;
    for (idx, case) in cases.iter().enumerate() {
        let got = evaluate_url(&case.url);
        if got != case.expected {
            eprintln!(
                "URL VECTOR MISMATCH at index {}:\n  URL: {}\n  Expected: {}\n  Actual:   {}",
                idx, case.url, case.expected, got
            );
            failed += 1;
        }
    }

    if failed > 0 {
        Err(format!("{} url vectors failed", failed))
    } else {
        Ok(cases.len())
    }
}

fn validate_ingest_cases(
    secret_file_cases: &[SecretFileCase],
    junk_dir_cases: &[JunkDirCase],
    secret_content_cases: &[SecretContentCase],
    sanitize_terminal_cases: &[SanitizeTerminalCase],
    sanitize_text_cases: &[SanitizeTextCase],
    sanitize_header_cases: &[SanitizeHeaderCase],
    envelope_cases: &[EnvelopeCase],
) -> (usize, usize) {
    let mut total = 0usize;
    let mut failed = 0usize;

    for c in secret_file_cases {
        total += 1;
        match std::panic::catch_unwind(|| is_secret_file(&c.path)) {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "INGEST SECRET_FILE MISMATCH for '{}': expected {}, got {}",
                    c.path, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("INGEST SECRET_FILE PANIC for '{}'", c.path);
                failed += 1;
            }
        }
    }

    for c in junk_dir_cases {
        total += 1;
        match std::panic::catch_unwind(|| is_junk_dir(&c.dirname)) {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "INGEST JUNK_DIR MISMATCH for '{}': expected {}, got {}",
                    c.dirname, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("INGEST JUNK_DIR PANIC for '{}'", c.dirname);
                failed += 1;
            }
        }
    }

    for c in secret_content_cases {
        total += 1;
        let joined = c.text_parts.concat();
        let fp = c.file_path.as_deref();
        match std::panic::catch_unwind(|| scan_secret_content(&joined, fp).map(|s| s.to_string())) {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "INGEST SECRET_CONTENT MISMATCH for '{}' (path={:?}): expected {:?}, got {:?}",
                    c.id, c.file_path, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!(
                    "INGEST SECRET_CONTENT PANIC for '{}' (path={:?})",
                    c.id, c.file_path
                );
                failed += 1;
            }
        }
    }

    for c in sanitize_terminal_cases {
        total += 1;
        match std::panic::catch_unwind(|| sanitize_terminal_output(&c.input)) {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "INGEST SANITIZE_TERMINAL MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                    c.id, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("INGEST SANITIZE_TERMINAL PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    for c in sanitize_text_cases {
        total += 1;
        match std::panic::catch_unwind(|| sanitize_text_content(&c.raw_utf8, c.max_line_length)) {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "INGEST SANITIZE_TEXT MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                    c.id, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("INGEST SANITIZE_TEXT PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    for c in sanitize_header_cases {
        total += 1;
        match std::panic::catch_unwind(|| sanitize_header(&c.header)) {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "INGEST SANITIZE_HEADER MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                    c.id, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("INGEST SANITIZE_HEADER PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    for c in envelope_cases {
        total += 1;
        let res = std::panic::catch_unwind(|| {
            let got_defanged = defang_envelope_markers(&c.content, Some(&c.nonce));
            let got_env = wrap_untrusted_envelope(&c.content, c.header.as_deref(), &c.nonce);
            (got_defanged, got_env)
        });
        match res {
            Ok((got_defanged, got_env))
                if got_defanged == c.expected_defanged && got_env == c.expected_envelope => {}
            Ok((got_defanged, got_env)) => {
                eprintln!(
                    "INGEST ENVELOPE MISMATCH for '{}':\n  expected_defanged: {:?}\n  got_defanged:      {:?}\n  expected_env: {:?}\n  got_env:      {:?}",
                    c.id, c.expected_defanged, got_defanged, c.expected_envelope, got_env
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("INGEST ENVELOPE PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    (total, failed)
}

pub fn run_ingest_conformance(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let vec_file: IngestVectorsFile = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut failed = 0usize;
    let got_limits = get_ingest_limits();
    if got_limits != vec_file.limits {
        eprintln!(
            "INGEST LIMITS MISMATCH:\n  expected: {:?}\n  got:      {:?}",
            vec_file.limits, got_limits
        );
        failed += 1;
    }

    let (case_count, case_failed) = validate_ingest_cases(
        &vec_file.secret_file_cases,
        &vec_file.junk_dir_cases,
        &vec_file.secret_content_cases,
        &vec_file.sanitize_terminal_cases,
        &vec_file.sanitize_text_cases,
        &vec_file.sanitize_header_cases,
        &vec_file.envelope_cases,
    );
    failed += case_failed;

    if failed > 0 {
        Err(format!("{} ingest vectors failed", failed))
    } else {
        Ok(case_count)
    }
}

fn validate_verify_loop_cases(
    codec_roundtrip_cases: &[CodecRoundtripCase],
    codec_invalid_envelope_cases: &[CodecInvalidEnvelopeCase],
    codec_envelope_json_cases: &[CodecEnvelopeJsonDiffCase],
    verdict_frame_cases: &[VerdictFrameCase],
    example_extraction_cases: &[CanonicalExampleExtractionCase],
) -> (usize, usize) {
    let mut total = 0usize;
    let mut failed = 0usize;

    for c in codec_roundtrip_cases {
        total += 1;
        let res = std::panic::catch_unwind(|| {
            let decoded = decode_value(&c.encoded).map_err(|e| e.to_string())?;
            let got_type = decoded.python_type_name().to_string();
            let re_encoded = encode_value(&decoded).map_err(|e| e.to_string())?;
            Ok::<(String, serde_json::Value), String>((got_type, re_encoded))
        });
        match res {
            Ok(Ok((got_type, re_encoded)))
                if got_type == c.python_type && re_encoded == c.encoded => {}
            Ok(Ok((got_type, re_encoded))) => {
                eprintln!(
                    "VERIFY_LOOP CODEC_ROUNDTRIP MISMATCH for '{}':\n  expected_type: {}, got_type: {}\n  expected_enc: {}\n  got_enc:      {}",
                    c.id, c.python_type, got_type, c.encoded, re_encoded
                );
                failed += 1;
            }
            Ok(Err(e)) => {
                eprintln!("VERIFY_LOOP CODEC_ROUNDTRIP ERROR for '{}': {}", c.id, e);
                failed += 1;
            }
            Err(_) => {
                eprintln!("VERIFY_LOOP CODEC_ROUNDTRIP PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    for c in codec_invalid_envelope_cases {
        total += 1;
        match std::panic::catch_unwind(|| decode_value(&c.envelope)) {
            Ok(Err(_)) => {}
            Ok(Ok(val)) => {
                eprintln!(
                    "VERIFY_LOOP CODEC_INVALID MISMATCH for '{}': expected error ({}), got Ok({:?})",
                    c.id, c.expected_error, val
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("VERIFY_LOOP CODEC_INVALID PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    for c in codec_envelope_json_cases {
        total += 1;
        let res = std::panic::catch_unwind(|| match decode_envelope_json(&c.raw_json) {
            Ok(decoded) => {
                let py_type = decoded.python_type_name().to_string();
                match encode_value_strict(&decoded) {
                    Ok(strict_enc) => {
                        let canonical = strict_enc.to_python_canonical_json();
                        (true, Some(py_type), Some(canonical))
                    }
                    Err(_) => (false, None, None),
                }
            }
            Err(_) => (false, None, None),
        });
        match res {
            Ok((got_ok, got_type, got_re_enc))
                if got_ok == c.expected_ok
                    && got_type == c.expected_python_type
                    && got_re_enc == c.expected_re_encoded_json => {}
            Ok((got_ok, got_type, got_re_enc)) => {
                eprintln!(
                    "VERIFY_LOOP CODEC_JSON_DIFF MISMATCH for '{}':\n  raw_json: {:?}\n  expected: ok={}, type={:?}, enc={:?}\n  got:      ok={}, type={:?}, enc={:?}",
                    c.id,
                    c.raw_json,
                    c.expected_ok,
                    c.expected_python_type,
                    c.expected_re_encoded_json,
                    got_ok,
                    got_type,
                    got_re_enc
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!(
                    "VERIFY_LOOP CODEC_JSON_DIFF PANIC for '{}': raw_json={:?}",
                    c.id, c.raw_json
                );
                failed += 1;
            }
        }
    }

    for c in verdict_frame_cases {
        total += 1;
        let res = std::panic::catch_unwind(|| {
            verify_verdict_frame(
                &c.stdout,
                &c.parent_nonce,
                &c.parent_hmac_key,
                &c.expected_test_ids,
                c.exit_code,
                &c.res_status,
                c.expected_test_hash.as_deref(),
            )
        });
        match res {
            Ok(got) if got == c.expected => {}
            Ok(got) => {
                eprintln!(
                    "VERIFY_LOOP VERDICT_FRAME MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                    c.id, c.expected, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("VERIFY_LOOP VERDICT_FRAME PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    for c in example_extraction_cases {
        total += 1;
        let ep_opt = if c.entry_point.is_empty() {
            None
        } else {
            Some(c.entry_point.as_str())
        };
        match std::panic::catch_unwind(|| extract_example_assertions(&c.prompt, ep_opt)) {
            Ok(got) if got == c.expected_statements => {}
            Ok(got) => {
                eprintln!(
                    "VERIFY_LOOP EXAMPLE_EXTRACTION MISMATCH for '{}' (ep={:?}):\n  prompt: {:?}\n  expected: {:?}\n  got:      {:?}",
                    c.id, c.entry_point, c.prompt, c.expected_statements, got
                );
                failed += 1;
            }
            Err(_) => {
                eprintln!("VERIFY_LOOP EXAMPLE_EXTRACTION PANIC for '{}'", c.id);
                failed += 1;
            }
        }
    }

    (total, failed)
}

pub fn run_verify_loop_conformance(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let vec_file: VerifyLoopVectorsFile = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut failed = 0usize;
    let got_policy = get_codec_policy();
    if got_policy != vec_file.codec_policy {
        eprintln!(
            "VERIFY_LOOP CODEC_POLICY MISMATCH:\n  expected: {:?}\n  got:      {:?}",
            vec_file.codec_policy, got_policy
        );
        failed += 1;
    }

    let (case_count, case_failed) = validate_verify_loop_cases(
        &vec_file.codec_roundtrip_cases,
        &vec_file.codec_invalid_envelope_cases,
        &[],
        &vec_file.verdict_frame_cases,
        &vec_file.canonical_example_extraction_cases,
    );
    failed += case_failed;

    if failed > 0 {
        Err(format!("{} verify_loop vectors failed", failed))
    } else {
        Ok(case_count)
    }
}

pub fn run_all_conformance(dir: &Path) -> Result<(usize, usize, usize, usize), String> {
    let tier_path = dir.join("tier_policy_vectors.json");
    let url_path = dir.join("url_policy_vectors.json");
    let ingest_path = dir.join("ingest_vectors.json");
    let verify_loop_path = dir.join("verify_loop_vectors.json");

    let tier_count = run_tier_conformance(&tier_path)?;
    let url_count = run_url_conformance(&url_path)?;
    let ingest_count = run_ingest_conformance(&ingest_path)?;
    let verify_loop_count = run_verify_loop_conformance(&verify_loop_path)?;

    Ok((tier_count, url_count, ingest_count, verify_loop_count))
}

pub fn run_differential_validation(path: &Path) -> Result<(usize, usize, usize, usize), String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let dataset: DifferentialDataset = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut tier_failed = 0;
    for (idx, case) in dataset.tier_cases.iter().enumerate() {
        let res = std::panic::catch_unwind(|| {
            calculate_budget(
                case.input.avail_ram_mb,
                case.input.memory_load_pct,
                case.input.cpu_load_pct,
                case.input.battery.clone(),
                case.input.cpu_cores,
            )
        });
        match res {
            Ok(got) if got == case.expected => {}
            Ok(got) => {
                eprintln!(
                    "DIFF TIER MISMATCH at index {}:\n  Input: {:?}\n  Expected: {:?}\n  Actual:   {:?}",
                    idx, case.input, case.expected, got
                );
                tier_failed += 1;
            }
            Err(_) => {
                eprintln!("DIFF TIER PANIC at index {}: Input: {:?}", idx, case.input);
                tier_failed += 1;
            }
        }
    }

    let mut url_failed = 0;
    for (idx, case) in dataset.url_cases.iter().enumerate() {
        match std::panic::catch_unwind(|| evaluate_url(&case.url)) {
            Ok(got) if got == case.expected => {}
            Ok(got) => {
                eprintln!(
                    "DIFF URL MISMATCH at index {}:\n  URL: {:?}\n  Expected: {}\n  Actual:   {}",
                    idx, case.url, case.expected, got
                );
                url_failed += 1;
            }
            Err(_) => {
                eprintln!("DIFF URL PANIC at index {}: URL: {:?}", idx, case.url);
                url_failed += 1;
            }
        }
    }

    let (ingest_count, ingest_failed) = validate_ingest_cases(
        &dataset.ingest_cases.secret_file_cases,
        &dataset.ingest_cases.junk_dir_cases,
        &dataset.ingest_cases.secret_content_cases,
        &dataset.ingest_cases.sanitize_terminal_cases,
        &dataset.ingest_cases.sanitize_text_cases,
        &dataset.ingest_cases.sanitize_header_cases,
        &dataset.ingest_cases.envelope_cases,
    );

    let (verify_loop_count, verify_loop_failed) = validate_verify_loop_cases(
        &dataset.verify_loop_cases.codec_roundtrip_cases,
        &dataset.verify_loop_cases.codec_invalid_envelope_cases,
        &dataset.verify_loop_cases.codec_envelope_json_cases,
        &dataset.verify_loop_cases.verdict_frame_cases,
        &dataset.verify_loop_cases.example_extraction_cases,
    );

    if tier_failed > 0 || url_failed > 0 || ingest_failed > 0 || verify_loop_failed > 0 {
        Err(format!(
            "Differential validation failed: {} tier mismatches, {} URL mismatches, {} ingest mismatches, {} verify_loop mismatches",
            tier_failed, url_failed, ingest_failed, verify_loop_failed
        ))
    } else {
        Ok((
            dataset.tier_cases.len(),
            dataset.url_cases.len(),
            ingest_count,
            verify_loop_count,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn find_conformance_dir() -> PathBuf {
        let candidates = [
            PathBuf::from("../research/conformance"),
            PathBuf::from("research/conformance"),
            PathBuf::from("../../research/conformance"),
        ];
        for c in &candidates {
            if c.exists() && c.join("tier_policy_vectors.json").exists() {
                return c.clone();
            }
        }
        PathBuf::from("../research/conformance")
    }

    #[test]
    fn test_tier_vectors_conformance() {
        let dir = find_conformance_dir();
        let path = dir.join("tier_policy_vectors.json");
        if path.exists() {
            let count = run_tier_conformance(&path).expect("Tier vectors must pass");
            assert!(count >= 200, "Must run at least 200 tier vectors");
        }
    }

    #[test]
    fn test_url_vectors_conformance() {
        let dir = find_conformance_dir();
        let path = dir.join("url_policy_vectors.json");
        if path.exists() {
            let count = run_url_conformance(&path).expect("URL vectors must pass");
            assert!(count >= 28, "Must run at least 28 URL vectors");
        }
    }

    #[test]
    fn test_ingest_vectors_conformance() {
        let dir = find_conformance_dir();
        let path = dir.join("ingest_vectors.json");
        assert!(
            path.exists(),
            "ingest_vectors.json must exist at {}",
            path.display()
        );
        let count =
            run_ingest_conformance(&path).expect("Ingest vectors must pass with 0 failures");
        assert!(
            count >= 112,
            "Must run at least 112 ingest vector cases (got {})",
            count
        );
    }

    #[test]
    fn test_verify_loop_vectors_conformance() {
        let dir = find_conformance_dir();
        let path = dir.join("verify_loop_vectors.json");
        assert!(
            path.exists(),
            "verify_loop_vectors.json must exist at {}",
            path.display()
        );
        let count = run_verify_loop_conformance(&path)
            .expect("Verify-loop vectors must pass with 0 failures");
        assert!(
            count >= 58,
            "Must run at least 58 verify-loop vector cases (got {})",
            count
        );
    }
}
