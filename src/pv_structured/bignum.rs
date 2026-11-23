// SPDX-License-Identifier: MIT OR Apache-2.0
//! Small unsigned big integers for the checks of keys: the product of the primes of an RSA key, the congruences of
//! its exponents, and the equation of an elliptic curve.

use std::cmp::Ordering;

/// An unsigned integer: 32-bit limbs, the least significant first, without a zero limb at the end.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Uint(Vec<u32>);

impl Uint {
    /// The integer of big-endian bytes.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len() / 4 + 1);
        for chunk in bytes.rchunks(4) {
            let mut limb = 0u32;
            for byte in chunk {
                limb = (limb << 8) | u32::from(*byte);
            }
            limbs.push(limb);
        }
        let mut value = Self(limbs);
        value.normalize();
        value
    }

    /// The integer of a text of hexadecimal digits.
    pub fn from_hex(text: &str) -> Self {
        let digits: Vec<u8> = text
            .bytes()
            .filter_map(|byte| (byte as char).to_digit(16))
            .map(|digit| digit as u8)
            .collect();
        let mut bytes = Vec::with_capacity(digits.len() / 2 + 1);
        let mut index = digits.len();
        while index > 0 {
            let low = digits[index - 1];
            let high = if index >= 2 { digits[index - 2] } else { 0 };
            bytes.push(high << 4 | low);
            index = index.saturating_sub(2);
        }
        bytes.reverse();
        Self::from_be_bytes(&bytes)
    }

    /// The integer of a small number.
    pub fn from_u64(value: u64) -> Self {
        let mut number = Self(vec![value as u32, (value >> 32) as u32]);
        number.normalize();
        number
    }

    fn normalize(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    /// True for zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of bits.
    pub fn bit_length(&self) -> usize {
        match self.0.last() {
            None => 0,
            Some(top) => self.0.len() * 32 - top.leading_zeros() as usize,
        }
    }

    fn bit(&self, index: usize) -> bool {
        self.0.get(index / 32).is_some_and(|limb| limb >> (index % 32) & 1 == 1)
    }

    /// The sum.
    pub fn add(&self, other: &Self) -> Self {
        let mut limbs = Vec::with_capacity(self.0.len().max(other.0.len()) + 1);
        let mut carry = 0u64;
        for index in 0..self.0.len().max(other.0.len()) {
            let sum =
                u64::from(*self.0.get(index).unwrap_or(&0)) + u64::from(*other.0.get(index).unwrap_or(&0)) + carry;
            limbs.push(sum as u32);
            carry = sum >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
        let mut value = Self(limbs);
        value.normalize();
        value
    }

    /// The difference. The value must not be below `other`: a smaller value gives zero.
    pub fn sub(&self, other: &Self) -> Self {
        if *self < *other {
            return Self::default();
        }
        let mut result = self.clone();
        result.sub_assign(other);
        result
    }

    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i64;
        for index in 0..self.0.len() {
            let mut value = i64::from(self.0[index]) - i64::from(*other.0.get(index).unwrap_or(&0)) - borrow;
            if value < 0 {
                value += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            self.0[index] = value as u32;
        }
        self.normalize();
    }

    /// The product.
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::default();
        }
        let mut limbs = vec![0u32; self.0.len() + other.0.len()];
        for (index, left) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (offset, right) in other.0.iter().enumerate() {
                let current = u64::from(limbs[index + offset]) + u64::from(*left) * u64::from(*right) + carry;
                limbs[index + offset] = current as u32;
                carry = current >> 32;
            }
            limbs[index + other.0.len()] = carry as u32;
        }
        let mut value = Self(limbs);
        value.normalize();
        value
    }

    fn shift_in(&mut self, bit: bool) {
        let mut carry = u32::from(bit);
        for limb in &mut self.0 {
            let next = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if carry > 0 {
            self.0.push(carry);
        }
    }

    /// The remainder of the division by a modulus that is not zero.
    pub fn rem(&self, modulus: &Self) -> Self {
        let mut remainder = Self(Vec::with_capacity(modulus.0.len() + 1));
        if modulus.is_zero() {
            return remainder;
        }
        for index in (0..self.bit_length()).rev() {
            remainder.shift_in(self.bit(index));
            remainder.normalize();
            if remainder >= *modulus {
                remainder.sub_assign(modulus);
            }
        }
        remainder
    }
}

impl PartialOrd for Uint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Uint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }
}

/// The prime of the field and the constant `b` of the curve `y^2 = x^3 - 3x + b`, as hexadecimal text.
fn curve_constants(curve: &str) -> (&'static str, &'static str) {
    match curve {
        "P-224" => (
            "ffffffffffffffffffffffffffffffff000000000000000000000001",
            "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        ),
        "P-256" => (
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        ),
        "P-384" => (
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        ),
        _ => (
            "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        ),
    }
}

/// True when the point is on the curve: both coordinates are below the prime of the field and the equation holds.
pub fn point_on_curve(curve: &str, x: &[u8], y: &[u8]) -> bool {
    let (prime, constant) = curve_constants(curve);
    let prime = Uint::from_hex(prime);
    let constant = Uint::from_hex(constant);
    let x = Uint::from_be_bytes(x);
    let y = Uint::from_be_bytes(y);
    if x >= prime || y >= prime {
        return false;
    }
    let left = y.mul(&y).rem(&prime);
    let cube = x.mul(&x).rem(&prime).mul(&x).rem(&prime);
    let three_x = x.mul(&Uint::from_u64(3)).rem(&prime);
    let right = cube.add(&constant).add(&prime).sub(&three_x).rem(&prime);
    left == right
}

/// The order of the group of a curve.
pub fn curve_order(curve: &str) -> Uint {
    Uint::from_hex(match curve {
        "P-224" => "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
        "P-256" => "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "P-384" => "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        _ => {
            "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
        }
    })
}
