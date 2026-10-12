//! Conformance vector runner (VS2 & Phase 2 Slice 1 Safe Ingestion)
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

#[derive(Debug, Deserialize)]
pub struct DifferentialDataset {
    pub tier_cases: Vec<TierVectorCase>,
    pub url_cases: Vec<UrlVectorCase>,
    #[serde(default)]
    pub ingest_cases: IngestDifferentialCases,
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
        let got = is_secret_file(&c.path);
        if got != c.expected {
            eprintln!(
                "INGEST SECRET_FILE MISMATCH for '{}': expected {}, got {}",
                c.path, c.expected, got
            );
            failed += 1;
        }
    }

    for c in junk_dir_cases {
        total += 1;
        let got = is_junk_dir(&c.dirname);
        if got != c.expected {
            eprintln!(
                "INGEST JUNK_DIR MISMATCH for '{}': expected {}, got {}",
                c.dirname, c.expected, got
            );
            failed += 1;
        }
    }

    for c in secret_content_cases {
        total += 1;
        let joined = c.text_parts.concat();
        let got = scan_secret_content(&joined, c.file_path.as_deref()).map(|s| s.to_string());
        if got != c.expected {
            eprintln!(
                "INGEST SECRET_CONTENT MISMATCH for '{}' (path={:?}): expected {:?}, got {:?}",
                c.id, c.file_path, c.expected, got
            );
            failed += 1;
        }
    }

    for c in sanitize_terminal_cases {
        total += 1;
        let got = sanitize_terminal_output(&c.input);
        if got != c.expected {
            eprintln!(
                "INGEST SANITIZE_TERMINAL MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                c.id, c.expected, got
            );
            failed += 1;
        }
    }

    for c in sanitize_text_cases {
        total += 1;
        let got = sanitize_text_content(&c.raw_utf8, c.max_line_length);
        if got != c.expected {
            eprintln!(
                "INGEST SANITIZE_TEXT MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                c.id, c.expected, got
            );
            failed += 1;
        }
    }

    for c in sanitize_header_cases {
        total += 1;
        let got = sanitize_header(&c.header);
        if got != c.expected {
            eprintln!(
                "INGEST SANITIZE_HEADER MISMATCH for '{}':\n  expected: {:?}\n  got:      {:?}",
                c.id, c.expected, got
            );
            failed += 1;
        }
    }

    for c in envelope_cases {
        total += 1;
        let got_defanged = defang_envelope_markers(&c.content, Some(&c.nonce));
        let got_env = wrap_untrusted_envelope(&c.content, c.header.as_deref(), &c.nonce);
        if got_defanged != c.expected_defanged || got_env != c.expected_envelope {
            eprintln!(
                "INGEST ENVELOPE MISMATCH for '{}':\n  expected_defanged: {:?}\n  got_defanged:      {:?}\n  expected_env: {:?}\n  got_env:      {:?}",
                c.id, c.expected_defanged, got_defanged, c.expected_envelope, got_env
            );
            failed += 1;
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

pub fn run_all_conformance(dir: &Path) -> Result<(usize, usize, usize), String> {
    let tier_path = dir.join("tier_policy_vectors.json");
    let url_path = dir.join("url_policy_vectors.json");
    let ingest_path = dir.join("ingest_vectors.json");

    let tier_count = run_tier_conformance(&tier_path)?;
    let url_count = run_url_conformance(&url_path)?;
    let ingest_count = run_ingest_conformance(&ingest_path)?;

    Ok((tier_count, url_count, ingest_count))
}

pub fn run_differential_validation(path: &Path) -> Result<(usize, usize, usize), String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let dataset: DifferentialDataset = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut tier_failed = 0;
    for (idx, case) in dataset.tier_cases.iter().enumerate() {
        let got = calculate_budget(
            case.input.avail_ram_mb,
            case.input.memory_load_pct,
            case.input.cpu_load_pct,
            case.input.battery.clone(),
            case.input.cpu_cores,
        );
        if got != case.expected {
            eprintln!(
                "DIFF TIER MISMATCH at index {}:\n  Input: {:?}\n  Expected: {:?}\n  Actual:   {:?}",
                idx, case.input, case.expected, got
            );
            tier_failed += 1;
        }
    }

    let mut url_failed = 0;
    for (idx, case) in dataset.url_cases.iter().enumerate() {
        let got = evaluate_url(&case.url);
        if got != case.expected {
            eprintln!(
                "DIFF URL MISMATCH at index {}:\n  URL: {:?}\n  Expected: {}\n  Actual:   {}",
                idx, case.url, case.expected, got
            );
            url_failed += 1;
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

    if tier_failed > 0 || url_failed > 0 || ingest_failed > 0 {
        Err(format!(
            "Differential validation failed: {} tier mismatches, {} URL mismatches, {} ingest mismatches",
            tier_failed, url_failed, ingest_failed
        ))
    } else {
        Ok((dataset.tier_cases.len(), dataset.url_cases.len(), ingest_count))
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
        assert!(path.exists(), "ingest_vectors.json must exist at {}", path.display());
        let count = run_ingest_conformance(&path).expect("Ingest vectors must pass with 0 failures");
        assert_eq!(count, 99, "Must run all 99 ingest vector cases (got {})", count);
    }
}
