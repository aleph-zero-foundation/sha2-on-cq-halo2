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