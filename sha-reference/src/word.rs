#![allow(unused)]

use std::ops::{Add, BitXor};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Default)]
pub enum Bit {
    #[default]
    Zero,
    One,
}

impl Add for Bit {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Bit::Zero, Bit::Zero) | (Bit::One, Bit::One) => Bit::Zero,
            _ => Bit::One,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Word<const L: usize> {
    bits: [Bit; L],
}

pub type Limb<const L: usize> = Word<L>;

impl<const L: usize> Word<L> {
    pub fn zero() -> Self {
        Self { bits: [Bit::Zero; L] }
    }

    pub fn right_rotation(&self, n: usize) -> Self {
        let mut result = Self::zero();
        for i in 0..L {
            result.bits[i] = self.bits[(i + L - n) % L];
        }
        result
    }

    pub fn rot_0(&self) -> Self {
        self.right_rotation(2) ^ self.right_rotation(13) ^ self.right_rotation(22)
    }

    pub fn rot_1(&self) -> Self {
        self.right_rotation(6) ^ self.right_rotation(11) ^ self.right_rotation(25)
    }
}

pub fn majority<const L: usize>(a: &Word<L>, b: &Word<L>, c: &Word<L>) -> Word<L> {
    let mut result = Word::zero();
    for i in 0..L {
        result.bits[i] = match (a.bits[i], b.bits[i], c.bits[i]) {
            (Bit::Zero, Bit::Zero, Bit::Zero)
            | (Bit::Zero, Bit::Zero, Bit::One)
            | (Bit::Zero, Bit::One, Bit::Zero)
            | (Bit::One, Bit::Zero, Bit::Zero) => Bit::Zero,
            _ => Bit::One,
        };
    }
    result
}

pub fn choose<const L: usize>(a: &Word<L>, b: &Word<L>, c: &Word<L>) -> Word<L> {
    let mut result = Word::zero();
    for i in 0..L {
        let (r#if, then, r#else) = (a.bits[i], b.bits[i], c.bits[i]);
        result.bits[i] = if r#if == Bit::One { then } else { r#else };
    }
    result
}

impl<const L: usize> BitXor for Word<L> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut result = Self::zero();
        for i in 0..L {
            result.bits[i] = match (self.bits[i], rhs.bits[i]) {
                (Bit::Zero, Bit::Zero) | (Bit::One, Bit::One) => Bit::Zero,
                (Bit::One, Bit::Zero) | (Bit::Zero, Bit::One) => Bit::One,
            };
        }
        result
    }
}

impl<const L: usize> Add for Word<L> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = Self::zero();
        for i in 0..L {
            result.bits[i] = self.bits[i] + rhs.bits[i];
        }
        result
    }
}
