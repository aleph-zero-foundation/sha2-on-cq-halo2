pub use crate::word::Word;
use crate::word::{choose, majority};

mod word;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Octet<const L: usize> {
    a: Word<L>,
    b: Word<L>,
    c: Word<L>,
    d: Word<L>,
    e: Word<L>,
    f: Word<L>,
    g: Word<L>,
    h: Word<L>,
}

pub fn sha_round<const L: usize>(input: Octet<L>) -> Octet<L> {
    let mut output = input;

    output.b = input.a;
    output.c = input.b;
    output.d = input.c;
    output.f = input.e;
    output.g = input.f;
    output.h = input.g;

    let temp = input.h + input.e.rot_1() + choose(&input.e, &input.f, &input.g);
    output.e = input.d + temp;
    output.a = temp + input.a.rot_0() + majority(&input.a, &input.b, &input.c);

    output
}

pub fn sha<const L: usize>(input: Octet<L>) -> Octet<L> {
    let mut output = input;

    for _ in 0..64 {
        output = sha_round(output);
    }

    output
}

#[cfg(test)]
mod tests{
    use crate::{Octet, Word};
    use crate::word::Bit::{One, Zero};

    /// Test input on 2-bit words:
    /// a: 00, b: 01, c: 10, d: 11, e: 00, f: 01, g: 10, h: 11
    #[test]
    fn test_single_round() {
        let input = Octet {
            a: Word::from([Zero, Zero]),
            b: Word::from([Zero, One]),
            c: Word::from([One, Zero]),
            d: Word::from([One, One]),
            e: Word::from([Zero, Zero]),
            f: Word::from([Zero, One]),
            g: Word::from([One, Zero]),
            h: Word::from([One, One]),
        };

        let expected = Octet {
            b: Word::from([Zero, Zero]), // copied a
            c: Word::from([Zero, One]),  // copied b
            d: Word::from([One, Zero]),  // copied c
            f: Word::from([Zero, Zero]), // copied e
            g: Word::from([Zero, One]),  // copied f
            h: Word::from([One, Zero]),  // copied g

            e: Word::from([One, Zero]),  // d + h + e.rot_1() + choose(e, f, g)
            a: Word::from([Zero, One]),  //     h + e.rot_1() + choose(e, f, g) + a.rot_0() + majority(a, b, c)
        };

        let output = super::sha_round(input);
        assert_eq!(output, expected);
    }
}
