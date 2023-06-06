use ff::Field;
use halo2curves::pairing::{Engine, MultiMillerLoop};
use rand_core::OsRng;

pub(crate) mod prover;
pub(crate) mod verifier;

use std::{collections::BTreeMap, io};

use crate::{
    arithmetic::best_multiexp,
    helpers::SerdePrimeField,
    poly::{kzg::commitment::ParamsKZG, EvaluationDomain},
    SerdeFormat,
};

use super::Expression;

pub fn is_pow_2(x: usize) -> bool {
    (x & (x - 1)) == 0
}

fn log2(x: usize) -> u32 {
    (usize::BITS - 1) - x.leading_zeros()
}

#[derive(Debug, Clone)]
pub struct StaticTable<E: MultiMillerLoop> {
    pub opened: Option<StaticTableValues<E>>,
    pub committed: Option<StaticCommittedTable<E>>,
}

/// Abstract type that allows to store MAP(table_id => static_table) in proving(verifying) key
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct StaticTableId<T: Clone + Ord>(pub T);

impl<T: Clone + Ord> StaticTableId<T> {
    pub fn id(&self) -> &T {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct StaticTableValues<E: MultiMillerLoop> {
    size: usize,
    /// Mapping from value to its index in the table
    value_index_mapping: BTreeMap<E::Scalar, usize>,
}

impl<E: MultiMillerLoop> StaticTableValues<E> {
    pub fn commit(&self, srs_g2: &[E::G2Affine]) -> StaticCommittedTable<E> {
        let domain = EvaluationDomain::<E::Scalar>::new(2, log2(self.size));
        // zv = x^n - 1
        assert!(is_pow_2(self.size));
        let zv = srs_g2[self.size] - srs_g2[0];

        let mut table_coeffs: Vec<E::Scalar> = self.value_index_mapping.keys().cloned().collect();
        EvaluationDomain::<E::Scalar>::ifft(
            table_coeffs.as_mut_slice(),
            domain.get_omega_inv(),
            log2(self.size),
            domain.ifft_divisor(),
        );
        let t = best_multiexp(&table_coeffs, &srs_g2[..table_coeffs.len()]);
        StaticCommittedTable {
            zv: zv.into(),
            t: t.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticCommittedTable<E: MultiMillerLoop> {
    pub zv: E::G2Affine,
    pub t: E::G2Affine,
}

#[derive(Debug, Clone)]
pub struct Argument<F: Field> {
    input: Expression<F>,
    table_id: StaticTableId<String>,
}

impl<F: Field> Argument<F> {
    pub fn new(name: &'static str, input: Expression<F>, table_id: StaticTableId<String>) -> Self {
        Self { input, table_id }
    }
}

#[test]
fn test_table() {
    use halo2curves::bn256::{Bn256, Fr};
    const N: u32 = 8;
    let params = ParamsKZG::<Bn256>::setup(N - 1, N, OsRng);

    let table = StaticTableValues::<Bn256> {
        size: 8,
        value_index_mapping: (0..N).map(|i| (Fr::random(OsRng), i as usize)).collect(),
    };

    let _ = table.commit(&params.g2_srs);
}
