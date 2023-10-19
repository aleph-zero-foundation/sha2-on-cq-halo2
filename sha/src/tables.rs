use crate::tables::limbs::{Bits, Limbs};

type Table = Vec<(u64, u64, u64, u64)>;

mod limbs {
    use std::ops::{BitAnd, BitOr, BitXor, Range, Shl, Shr};

    pub trait Bits:
        Copy
        + Shr<usize, Output = Self>
        + Shl<u8, Output = Self>
        + BitAnd<Self, Output = Self>
        + BitOr<Self, Output = Self>
        + From<u8>
        + TryInto<u8>
    {
        const BITS_LEN: usize;
        fn to_bits(self) -> Vec<u8> {
            (0..Self::BITS_LEN)
                .rev()
                .map(|n| ((self >> n) & 1.into()).try_into().map_err(|_| ()).unwrap())
                .collect()
        }

        fn from_bits(bits: Vec<u8>) -> Self {
            bits.iter()
                .fold(0.into(), |acc, &bit| (acc << 1) | (bit.into()))
        }
    }
    impl Bits for u8 {
        const BITS_LEN: usize = 8;
    }
    impl Bits for u16 {
        const BITS_LEN: usize = 8;
    }
    impl Bits for u32 {
        const BITS_LEN: usize = 8;
    }

    pub trait Limbs {
        type FullWord: Copy
            + Bits
            + BitXor<Self::FullWord, Output = Self::FullWord>
            + BitOr<Self::FullWord, Output = Self::FullWord>
            + TryFrom<u64>
            + TryInto<u64>;
        const FIRST_LIMB_LEN: u8;
        const SECOND_LIMB_LEN: u8;

        fn first_limb_rg() -> Range<u64> {
            0..(1 << Self::FIRST_LIMB_LEN)
        }

        fn second_limb_rg() -> Range<u64> {
            0..(1 << Self::SECOND_LIMB_LEN)
        }

        fn full_word_len() -> u8 {
            Self::FIRST_LIMB_LEN + Self::SECOND_LIMB_LEN + Self::SECOND_LIMB_LEN
        }
    }

    pub struct ShortLimbs;
    impl Limbs for ShortLimbs {
        type FullWord = u16;
        const FIRST_LIMB_LEN: u8 = 6;
        const SECOND_LIMB_LEN: u8 = 5;
    }

    pub struct LongLimbs;
    impl Limbs for LongLimbs {
        type FullWord = u32;
        const FIRST_LIMB_LEN: u8 = 12;
        const SECOND_LIMB_LEN: u8 = 10;
    }
}

fn create_synthesis_table<L: Limbs>(f: impl Fn(u64, u64, u64) -> u64) -> Table {
    let mut table = vec![];
    for x in L::first_limb_rg() {
        for y in L::second_limb_rg() {
            for z in L::second_limb_rg() {
                table.push((x, y, z, f(x, y, z)));
            }
        }
    }

    table
}

fn combine<L: Limbs>(x: u64, y: u64, z: u64) -> L::FullWord {
    ((x << (L::SECOND_LIMB_LEN + L::SECOND_LIMB_LEN)) | (y << L::SECOND_LIMB_LEN) | z)
        .try_into()
        .map_err(|_| ())
        .unwrap()
}

fn rotation<L: Limbs, const N: usize>(word: L::FullWord) -> L::FullWord {
    let mut bits = word.to_bits();
    let rot = N % bits.len();
    bits.rotate_right(rot);
    L::FullWord::from_bits(bits)
}

fn create_rotation_table<L: Limbs, const R1: usize, const R2: usize, const R3: usize>() -> Table {
    create_synthesis_table::<L>(|x, y, z| {
        let xyz = combine::<L>(x, y, z);
        let rot0 = rotation::<L, R1>(xyz) ^ rotation::<L, R2>(xyz) ^ rotation::<L, R3>(xyz);
        rot0.try_into().map_err(|_| ()).unwrap()
    })
}

pub fn create_rot0_table<L: Limbs>() -> Table {
    create_rotation_table::<L, 2, 13, 22>()
}

pub fn create_rot1_table<L: Limbs>() -> Table {
    create_rotation_table::<L, 6, 11, 25>()
}

pub fn create_maj_table<L: Limbs>() -> Table {
    create_synthesis_table::<L>(|x, y, z| {
        let maj = (x & y) ^ (x & z) ^ (y & z);
        maj.try_into().map_err(|_| ()).unwrap()
    })
}

pub fn create_ch_table<L: Limbs>() -> Table {
    create_synthesis_table::<L>(|x, y, z| {
        let ch = (x & y) ^ ((!x) & z);
        ch.try_into().map_err(|_| ()).unwrap()
    })
}

#[cfg(test)]
mod tests {
    use crate::tables::{create_rot0_table, create_rot1_table};
    use crate::tables::limbs::Limbs;

    struct TestLimbs;
    impl Limbs for TestLimbs {
        type FullWord = u8;
        const FIRST_LIMB_LEN: u8 = 4;
        const SECOND_LIMB_LEN: u8 = 2;
    }

    #[test]
    fn rot0_works() {
        let table = create_rot0_table::<TestLimbs>();
        assert_eq!(table.len(), 256);
        assert!(table.contains(&(0, 0, 0, 0)));
        assert!(table.contains(&(0b0000_1100, 0b000000_01, 0b000000_00, 0b0000_0100)));
        assert!(table.contains(&(0b0000_1010, 0b000000_01, 0b000000_10, 0b0000_0110)));
    }

    #[test]
    fn rot1_works() {
        let table = create_rot1_table::<TestLimbs>();
        assert_eq!(table.len(), 256);
        assert!(table.contains(&(0, 0, 0, 0)));
        assert!(table.contains(&(0b0000_1100, 0b000000_01, 0b000000_00, 0b1110_1001)));
        assert!(table.contains(&(0b0000_1010, 0b000000_01, 0b000000_10, 0b0001_1101)));
    }

    #[test]
    fn maj_works() {
        let table = crate::tables::create_maj_table::<TestLimbs>();
        assert_eq!(table.len(), 256);
        assert!(table.contains(&(0, 0, 0, 0)));
        assert!(table.contains(&(0b0000_1100, 0b000000_01, 0b000000_00, 0b0000_0000)));
        assert!(table.contains(&(0b0000_1010, 0b000000_01, 0b000000_10, 0b0000_0010)));
    }

    #[test]
    fn ch_works() {
        let table = crate::tables::create_ch_table::<TestLimbs>();
        assert_eq!(table.len(), 256);
        assert!(table.contains(&(0, 0, 0, 0)));
        assert!(table.contains(&(0b0000_1100, 0b000000_01, 0b000000_00, 0b0000_0000)));
        assert!(table.contains(&(0b0000_1010, 0b000000_01, 0b000000_10, 0b0000_0000)));
    }
}
