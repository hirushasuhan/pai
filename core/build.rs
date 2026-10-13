#![allow(clippy::all)]
use std::env;
use std::fs;
use std::path::Path;

struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut idx = (self.count as usize) & 0x3f;
        self.count += data.len() as u64;
        let mut pos = 0;
        if idx > 0 && idx + data.len() >= 64 {
            let needed = 64 - idx;
            self.buffer[idx..64].copy_from_slice(&data[..needed]);
            Self::transform(&mut self.state, &self.buffer);
            pos += needed;
            idx = 0;
        }
        while pos + 64 <= data.len() {
            let chunk: &[u8; 64] = data[pos..pos + 64].try_into().unwrap();
            Self::transform(&mut self.state, chunk);
            pos += 64;
        }
        if pos < data.len() {
            let rem = &data[pos..];
            self.buffer[idx..idx + rem.len()].copy_from_slice(rem);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.count * 8;
        let idx = (self.count as usize) & 0x3f;
        self.buffer[idx] = 0x80;
        let pad_len = if idx < 56 { 56 - idx - 1 } else { 64 + 56 - idx - 1 };
        for i in 0..pad_len {
            self.buffer[idx + 1 + i] = 0;
        }
        if idx >= 56 {
            Self::transform(&mut self.state, &self.buffer);
            self.buffer = [0u8; 64];
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        Self::transform(&mut self.state, &self.buffer);
        let mut out = [0u8; 32];
        for (i, val) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    fn transform(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (i, item) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(*item);
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
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let conformance_dir = Path::new(&manifest_dir).join("../research/conformance");

    let vector_files = [
        "tier_policy_vectors.json",
        "url_policy_vectors.json",
        "ingest_vectors.json",
        "verify_loop_vectors.json",
    ];

    let mut hasher = Sha256::new();
    let mut any_found = false;

    for vf in &vector_files {
        let p = conformance_dir.join(vf);
        println!("cargo:rerun-if-changed={}", p.display());
        if let Ok(bytes) = fs::read(&p) {
            hasher.update(vf.as_bytes());
            hasher.update(&bytes);
            any_found = true;
        }
    }

    let hash_hex = if any_found {
        to_hex(&hasher.finalize())
    } else {
        // Fallback constant if compiled without research directory
        "38909e2ae897dff3bd5bbabaf930546a951bbfeec4771ccf0e4a650a1f8768c1".to_string()
    };

    println!("cargo:rustc-env=PAI_CONFORMANCE_VECTORS_HASH={}", hash_hex);
}
