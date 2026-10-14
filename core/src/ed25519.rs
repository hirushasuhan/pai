//! Pure-Rust Ed25519 (RFC 8032 Section 5.1 / 6) Signature Verification & SHA-512.
//!
//! Provides strict, safe, zero-unsafe cryptographic verification:
//! - Pure-Rust FIPS 180-4 SHA-512
//! - Verification only for public inputs (branches on public signature and key data; not intended for secret signing operations)
//! - Canonical Curve25519 field arithmetic modulo p = 2^255 - 19
//! - Point decompression with strict y < p canonical checks
//! - Strict scalar verification rejecting malleated s >= L signatures
//! - RFC 8032 test vectors cross-checked

#![deny(unsafe_code)]

// ==============================================================================
// 1. SHA-512 (FIPS 180-4) Pure Rust Implementation
// ==============================================================================

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline(always)]
fn sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline(always)]
fn gamma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline(always)]
fn gamma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..80 {
        let t1 = h
            .wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let t2 = sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
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

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut state: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let total_len = data.len();
    let mut offset = 0;

    while offset + 128 <= total_len {
        let mut block = [0u8; 128];
        block.copy_from_slice(&data[offset..offset + 128]);
        sha512_compress(&mut state, &block);
        offset += 128;
    }

    let remainder = &data[offset..];
    let mut final_block = [0u8; 128];
    final_block[..remainder.len()].copy_from_slice(remainder);
    final_block[remainder.len()] = 0x80;

    let bit_len = (total_len as u128) * 8;
    if remainder.len() + 1 + 16 > 128 {
        sha512_compress(&mut state, &final_block);
        final_block = [0u8; 128];
    }
    final_block[112..128].copy_from_slice(&bit_len.to_be_bytes());
    sha512_compress(&mut state, &final_block);

    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ==============================================================================
// 2. Curve25519 Field Arithmetic Modulo p = 2^255 - 19
// ==============================================================================

/// 256-bit integer represented as 4 little-endian 64-bit limbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub [u64; 4]);

pub const P: [u64; 4] = [
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
];

pub const D: FieldElement = FieldElement([
    0x75eb4dca135978a3,
    0x00700a4d4141d8ab,
    0x8cc740797779e898,
    0x52036cee2b6ffe73,
]);

pub const SQRT_M1: FieldElement = FieldElement([
    0xc4ee1b274a0ea0b0,
    0x2f431806ad2fe478,
    0x2b4d00993dfbd7a7,
    0x2b8324804fc1df0b,
]);

pub const P_MINUS_2: [u64; 4] = [
    0xffffffffffffffeb,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
];

pub const P_PLUS_3_DIV_8: [u64; 4] = [
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x0fffffffffffffff,
];

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement([0, 0, 0, 0]);
    pub const ONE: FieldElement = FieldElement([1, 0, 0, 0]);

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// True if self >= other in 256-bit unsigned little-endian.
    #[inline]
    fn limbs_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    /// Adds two 4-limb integers, returning (sum, carry).
    #[inline]
    fn raw_add(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = (a[i] as u128) + (b[i] as u128) + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
        }
        (out, carry as u64)
    }

    /// Subtracts b from a (assuming a >= b).
    #[inline]
    fn raw_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = (a[i] as i128) - (b[i] as i128) - borrow;
            if diff < 0 {
                out[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = diff as u64;
                borrow = 0;
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        // clear bit 255
        limbs[3] &= 0x7fffffffffffffff;
        if Self::limbs_ge(&limbs, &P) {
            limbs = Self::raw_sub(&limbs, &P);
        }
        FieldElement(limbs)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = Self::raw_add(&self.0, &other.0);
        if carry > 0 || Self::limbs_ge(&sum, &P) {
            FieldElement(Self::raw_sub(&sum, &P))
        } else {
            FieldElement(sum)
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        if Self::limbs_ge(&self.0, &other.0) {
            FieldElement(Self::raw_sub(&self.0, &other.0))
        } else {
            let (added, _) = Self::raw_add(&self.0, &P);
            FieldElement(Self::raw_sub(&added, &other.0))
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = prod as u64;
                carry = prod >> 64;
            }
            let mut k = i + 4;
            while carry > 0 && k < 8 {
                let sum = (res[k] as u128) + carry;
                res[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        // Reduce modulo 2^255 - 19
        let lo = [res[0], res[1], res[2], res[3] & 0x7fffffffffffffff];
        let hi0 = (res[3] >> 63) | (res[4] << 1);
        let hi1 = (res[4] >> 63) | (res[5] << 1);
        let hi2 = (res[5] >> 63) | (res[6] << 1);
        let hi3 = (res[6] >> 63) | (res[7] << 1);
        let hi4 = res[7] >> 63;
        let hi = [hi0, hi1, hi2, hi3, hi4];

        // 19 * hi
        let mut hi_mul = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            let prod = (hi[i] as u128) * 19 + carry;
            hi_mul[i] = prod as u64;
            carry = prod >> 64;
        }

        // lo + 19 * hi
        let mut r = [0u64; 5];
        let mut add_carry = 0u128;
        for i in 0..4 {
            let sum = (lo[i] as u128) + (hi_mul[i] as u128) + add_carry;
            r[i] = sum as u64;
            add_carry = sum >> 64;
        }
        r[4] = (hi_mul[4] as u128).wrapping_add(add_carry) as u64;

        // second reduction
        let r_lo = [r[0], r[1], r[2], r[3] & 0x7fffffffffffffff];
        let r_hi = (r[3] >> 63) | (r[4] << 1);
        let r_hi_19 = (r_hi as u128) * 19;

        let mut out = [0u64; 4];
        let mut c_out = r_hi_19;
        for i in 0..4 {
            let sum = (r_lo[i] as u128) + c_out;
            out[i] = sum as u64;
            c_out = sum >> 64;
        }

        let final_hi = (out[3] >> 63) | ((c_out as u64) << 1);
        out[3] &= 0x7fffffffffffffff;
        let mut final_carry = (final_hi as u128) * 19;
        for item in &mut out {
            let sum = (*item as u128) + final_carry;
            *item = sum as u64;
            final_carry = sum >> 64;
        }

        if Self::limbs_ge(&out, &P) {
            FieldElement(Self::raw_sub(&out, &P))
        } else {
            FieldElement(out)
        }
    }

    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut res = FieldElement::ONE;
        let mut base = *self;
        for limb in exp {
            let mut l = *limb;
            for _ in 0..64 {
                if (l & 1) == 1 {
                    res = res.mul(&base);
                }
                base = base.mul(&base);
                l >>= 1;
            }
        }
        res
    }

    pub fn invert(&self) -> Self {
        self.pow(&P_MINUS_2)
    }
}

// ==============================================================================
// 3. Modulo q = 2^252 + 27742317777372353535851937790883648493 Scalar Reduction
// ==============================================================================

pub const Q: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0,
    0x1000000000000000,
];

pub fn scalar_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn scalar_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = (a[i] as i128) - (b[i] as i128) - borrow;
        if diff < 0 {
            out[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            out[i] = diff as u64;
            borrow = 0;
        }
    }
    out
}

/// Computes SHA-512 over data and reduces modulo q using 512-bit binary division.
pub fn sha512_modq(data: &[u8]) -> [u64; 4] {
    let digest = sha512(data);
    let mut h = [0u64; 8];
    for i in 0..8 {
        h[i] = u64::from_le_bytes(digest[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    let mut rem = [0u64; 4];
    for bit_pos in (0..512).rev() {
        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        let bit = (h[limb_idx] >> bit_idx) & 1;

        let mut carry = bit;
        for item in &mut rem {
            let next_carry = *item >> 63;
            *item = (*item << 1) | carry;
            carry = next_carry;
        }
        if scalar_ge(&rem, &Q) {
            rem = scalar_sub(&rem, &Q);
        }
    }
    rem
}

// ==============================================================================
// 4. Extended Point Operations on Twisted Edwards Curve
// ==============================================================================

#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

impl Point {
    pub const IDENTITY: Point = Point {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };
}

pub const BASE_POINT_G: Point = Point {
    x: FieldElement([
        0xc9562d608f25d51a,
        0x692cc7609525a7b2,
        0xc0a4e231fdd6dc5c,
        0x216936d3cd6e53fe,
    ]),
    y: FieldElement([
        0x6666666666666658,
        0x6666666666666666,
        0x6666666666666666,
        0x6666666666666666,
    ]),
    z: FieldElement::ONE,
    t: FieldElement([
        0x6dde8ab3a5b7dda3,
        0x20f09f80775152f5,
        0x66ea4e8e64abe37d,
        0x67875f0fd78b7665,
    ]),
};

pub fn point_add(p: &Point, q: &Point) -> Point {
    let a = p.y.sub(&p.x).mul(&q.y.sub(&q.x));
    let b = p.y.add(&p.x).mul(&q.y.add(&q.x));
    let c = FieldElement([2, 0, 0, 0]).mul(&p.t).mul(&q.t).mul(&D);
    let d = FieldElement([2, 0, 0, 0]).mul(&p.z).mul(&q.z);
    let e = b.sub(&a);
    let f = d.sub(&c);
    let g = d.add(&c);
    let h = b.add(&a);
    Point {
        x: e.mul(&f),
        y: g.mul(&h),
        z: f.mul(&g),
        t: e.mul(&h),
    }
}

pub fn point_equal(p: &Point, q: &Point) -> bool {
    p.x.mul(&q.z) == q.x.mul(&p.z) && p.y.mul(&q.z) == q.y.mul(&p.z)
}

pub fn point_mul(scalar: &[u64; 4], p: &Point) -> Point {
    let mut q = Point::IDENTITY;
    let mut base = *p;
    for limb in scalar {
        let mut l = *limb;
        for _ in 0..64 {
            if (l & 1) == 1 {
                q = point_add(&q, &base);
            }
            base = point_add(&base, &base);
            l >>= 1;
        }
    }
    q
}

fn recover_x(y: &FieldElement, sign: bool) -> Option<FieldElement> {
    let y2 = y.mul(y);
    let num = y2.sub(&FieldElement::ONE);
    let den = D.mul(&y2).add(&FieldElement::ONE);
    let x2 = num.mul(&den.invert());

    if x2.is_zero() {
        if sign {
            return None;
        } else {
            return Some(FieldElement::ZERO);
        }
    }

    let mut x = x2.pow(&P_PLUS_3_DIV_8);
    if x.mul(&x) != x2 {
        x = x.mul(&SQRT_M1);
    }
    if x.mul(&x) != x2 {
        return None;
    }

    let is_odd = (x.0[0] & 1) != 0;
    if is_odd != sign {
        x = FieldElement(P).sub(&x);
    }
    Some(x)
}

pub fn decompress_point(s: &[u8; 32]) -> Option<Point> {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes(s[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    let sign = (limbs[3] >> 63) != 0;
    limbs[3] &= 0x7fffffffffffffff;

    // Reject non-canonical y >= p
    if FieldElement::limbs_ge(&limbs, &P) {
        return None;
    }

    let y = FieldElement(limbs);
    let x = recover_x(&y, sign)?;
    let t = x.mul(&y);
    Some(Point {
        x,
        y,
        z: FieldElement::ONE,
        t,
    })
}

/// Returns true if `p` is a small-order point (order dividing 8).
/// In Ed25519 (cofactor 8), small-order points satisfy [8] P == IDENTITY.
pub fn is_small_order_point(p: &Point) -> bool {
    let p2 = point_add(p, p);
    let p4 = point_add(&p2, &p2);
    let p8 = point_add(&p4, &p4);
    point_equal(&p8, &Point::IDENTITY)
}

/// Validates a public key for trust root inclusion:
/// Must decompress to a valid curve point AND must not be a small-order point.
pub fn validate_trust_public_key(pk: &[u8; 32]) -> bool {
    match decompress_point(pk) {
        Some(p) => !is_small_order_point(&p),
        None => false,
    }
}

// ==============================================================================
// 5. Ed25519 Signature Verification
// ==============================================================================


/// Verifies an Ed25519 signature over `message` using 32-byte `public_key`.
///
/// Returns `true` if and only if:
/// 1. `public_key` is a valid canonical compressed Edwards curve point.
/// 2. Signature R (first 32 bytes) is a valid canonical compressed point.
/// 3. Signature s (second 32 bytes) is strictly less than group order L (rejects malleated signatures).
/// 4. `[s] B == R + [h] A` where `h = SHA-512(R || public_key || message) mod L`.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let a_point = match decompress_point(public_key) {
        Some(pt) => pt,
        None => return false,
    };

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[0..32]);
    let r_point = match decompress_point(&r_bytes) {
        Some(pt) => pt,
        None => return false,
    };

    let mut s_limbs = [0u64; 4];
    for i in 0..4 {
        s_limbs[i] = u64::from_le_bytes(signature[32 + i * 8..32 + (i + 1) * 8].try_into().unwrap());
    }

    // Reject s >= Q (RFC 8032 Section 5.1.7 requirement 1)
    if scalar_ge(&s_limbs, &Q) {
        return false;
    }

    let mut h_input = Vec::with_capacity(32 + 32 + message.len());
    h_input.extend_from_slice(&r_bytes);
    h_input.extend_from_slice(public_key);
    h_input.extend_from_slice(message);
    let h_scalar = sha512_modq(&h_input);

    let left = point_mul(&s_limbs, &BASE_POINT_G);
    let right = point_add(&r_point, &point_mul(&h_scalar, &a_point));
    point_equal(&left, &right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_empty_and_abc() {
        let empty = sha512(b"");
        let empty_hex: String = empty.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            empty_hex,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );

        let abc = sha512(b"abc");
        let abc_hex: String = abc.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            abc_hex,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_rfc8032_test_vector_1() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let mut pk = [0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&pk_hex[i * 2..i * 2 + 2], 16).unwrap();
        }

        let mut sig = [0u8; 64];
        for i in 0..64 {
            sig[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).unwrap();
        }

        assert!(verify(&pk, b"", &sig), "RFC 8032 vector 1 must verify");
        assert!(!verify(&pk, b"tampered", &sig), "Tampered message must fail verification");
    }

    #[test]
    fn test_malleated_signature_rejected() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let mut pk = [0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&pk_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let mut sig = [0u8; 64];
        for i in 0..64 {
            sig[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).unwrap();
        }

        // Add Q to s
        let mut s_limbs = [0u64; 4];
        for i in 0..4 {
            s_limbs[i] = u64::from_le_bytes(sig[32 + i * 8..32 + (i + 1) * 8].try_into().unwrap());
        }
        let (malleated_s, _) = FieldElement::raw_add(&s_limbs, &Q);
        for i in 0..4 {
            sig[32 + i * 8..32 + (i + 1) * 8].copy_from_slice(&malleated_s[i].to_le_bytes());
        }

        assert!(!verify(&pk, b"", &sig), "Malleated s >= Q signature must be rejected");
    }

    #[test]
    fn test_small_order_points_rejected_by_trust_validator() {
        // Identity point (order 1): y=1, x=0
        let mut id_pk = [0u8; 32];
        id_pk[0] = 1;
        assert!(!validate_trust_public_key(&id_pk), "Identity key must be rejected by trust validator");

        // Order 2 point: y = p - 1, x = 0
        let p2_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        let mut p2_pk = [0u8; 32];
        for i in 0..32 {
            p2_pk[i] = u8::from_str_radix(&p2_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert!(!validate_trust_public_key(&p2_pk), "Order-2 key must be rejected by trust validator");

        // Order 4 points: y = 0, x = +- sqrt(-1)
        let p4_pk1 = [0u8; 32];
        assert!(!validate_trust_public_key(&p4_pk1), "Order-4 key (sign 0) must be rejected");
        let mut p4_pk2 = [0u8; 32];
        p4_pk2[31] = 0x80;
        assert!(!validate_trust_public_key(&p4_pk2), "Order-4 key (sign 1) must be rejected");

        // Legitimate base point G (large prime order) must be accepted
        let g_compressed = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ];
        assert!(validate_trust_public_key(&g_compressed), "Base point G must be accepted");
    }

    #[test]
    fn test_conformance_ed25519_vectors_in_rust() {
        let vectors_json = include_str!("../../research/conformance/ed25519_vectors.json");
        let parsed: serde_json::Value = serde_json::from_str(vectors_json).expect("valid vectors JSON");
        let cases = parsed.get("cases").and_then(|v| v.as_array()).expect("cases array");
        assert!(cases.len() >= 176, "must have at least 176 test cases");

        for (idx, c) in cases.iter().enumerate() {
            let pk_hex = c["public_key_hex"].as_str().expect("pk hex");
            let msg_hex = c["message_hex"].as_str().expect("msg hex");
            let sig_hex = c["signature_hex"].as_str().expect("sig hex");
            let expected = c["expected"].as_bool().expect("expected bool");

            let mut pk = [0u8; 32];
            for i in 0..32 {
                pk[i] = u8::from_str_radix(&pk_hex[i * 2..i * 2 + 2], 16).expect("valid pk hex");
            }

            let mut sig = [0u8; 64];
            for i in 0..64 {
                sig[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).expect("valid sig hex");
            }

            let mut msg = Vec::with_capacity(msg_hex.len() / 2);
            for i in 0..msg_hex.len() / 2 {
                msg.push(u8::from_str_radix(&msg_hex[i * 2..i * 2 + 2], 16).expect("valid msg hex"));
            }

            let result = verify(&pk, &msg, &sig);
            assert_eq!(
                result,
                expected,
                "Case {} ({}) mismatch: expected {}, got {}",
                idx,
                c["id"].as_str().unwrap_or("?"),
                expected,
                result
            );
        }
    }
}

