//! Provides utility functions for cryptographic operations on Curve25519,
//! focusing on key generation and conversions between Montgomery (X25519)
//! and Edwards (Ed25519) curve forms.

use curve25519_dalek::traits::IsIdentity as _;
use curve25519_dalek::{
    EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT, montgomery::MontgomeryPoint,
};
use subtle::{Choice, ConditionallySelectable};

pub(crate) fn is_valid_public_key(pk: &[u8; 33]) -> bool {
    let decoded = match decode_public_key(pk) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Reject all-zero
    if decoded.iter().all(|&b| b == 0) {
        return false;
    }

    // Convert to Edwards (returns false if u-coordinate is not on the curve)
    let edwards = match try_convert_mont(decoded) {
        Some(pt) => pt,
        None => return false,
    };

    // Check not identity
    if edwards.is_identity() {
        return false;
    }

    // Check cofactor-cleared point not identity (catches low-order)
    if edwards.mul_by_cofactor().is_identity() {
        return false;
    }

    true
}

/// Converts a Montgomery u-coordinate (X25519) to a compressed Edwards point (Ed25519).
/// Panics if the u-coordinate does not correspond to a valid curve point.
pub(crate) fn u_to_y(u: [u8; 32]) -> EdwardsPoint {
    try_u_to_y(u).expect("Conversion from u-coordinate failed. Not all 32-byte arrays are valid points.")
}

/// Tries to convert a Montgomery u-coordinate to an Edwards point.
/// Returns None if the u-coordinate is not on the curve.
pub(crate) fn try_u_to_y(u: [u8; 32]) -> Option<EdwardsPoint> {
    let montgomery = MontgomeryPoint(u);
    montgomery.to_edwards(0)
}

/// Applies the Curve25519 "clamping" modification to a 32-byte private key.
pub(crate) fn clamp_private_key(mut u: [u8; 32]) -> [u8; 32] {
    u[0] &= 248;
    u[31] &= 127;
    u[31] |= 64;
    u
}

/// Calculates a "canonical" Ed25519 key pair from a 32-byte seed.
pub(crate) fn calculate_key_pair(u: [u8; 32]) -> (Scalar, EdwardsPoint) {
    let k = Scalar::from_bytes_mod_order(clamp_private_key(u));
    let ed = ED25519_BASEPOINT_POINT * k;

    let sign = (ed.compress().to_bytes()[31] >> 7) & 1;

    let priv_key = Scalar::conditional_select(&k, &-k, Choice::from(sign));
    let public_key = priv_key * ED25519_BASEPOINT_POINT;

    (priv_key, public_key)
}

/// Converts a Montgomery u-coordinate to an Edwards point.
/// Panics if the conversion fails. Use try_convert_mont for fallible conversion.
pub(crate) fn convert_mont(u: [u8; 32]) -> EdwardsPoint {
    let mut u_masked = u;
    u_masked[31] &= 127;
    u_to_y(u_masked)
}

/// Tries to convert a Montgomery u-coordinate to an Edwards point.
/// Returns None if the u-coordinate is not on the curve.
pub(crate) fn try_convert_mont(u: [u8; 32]) -> Option<EdwardsPoint> {
    let mut u_masked = u;
    u_masked[31] &= 127;
    try_u_to_y(u_masked)
}

/// Encodes a public key by prepending 0x05 (Curve25519) to the 32-byte key.
/// This is the native Rust API version.
pub fn encode_public_key(key: &[u8; 32]) -> [u8; 33] {
    let mut encoded = [0u8; 33];
    encoded[0] = 0x05;
    encoded[1..33].copy_from_slice(key);
    encoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength, // Although we input [u8; 33], keeping for semantic completeness if slice api is added later
    InvalidPrefix,
}

pub fn decode_public_key(key: &[u8; 33]) -> Result<[u8; 32], DecodeError> {
    if key[0] != 0x05 {
        return Err(DecodeError::InvalidPrefix);
    }
    let mut decoded = [0u8; 32];
    decoded.copy_from_slice(&key[1..]);
    Ok(decoded)
}
