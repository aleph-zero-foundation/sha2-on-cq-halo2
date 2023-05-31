use ff::Field;
use halo2curves::pairing::MultiMillerLoop;

mod prover;
mod verifier;

use std::{collections::BTreeMap, io};

use crate::{helpers::SerdePrimeField, SerdeFormat};

use super::Expression;

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

#[derive(Copy, Clone, Debug)]
pub struct StaticTableValues<E: MultiMillerLoop> {
    /// FIXME make constructor
    pub x: E::Scalar,
}

impl<E: MultiMillerLoop> StaticTableValues<E> {
    pub fn commit(&self, srs_g2: E::G2Affine) -> StaticCommittedTable<E> {
        StaticCommittedTable {
            x: (srs_g2 * self.x).into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticCommittedTable<E: MultiMillerLoop> {
    pub x: E::G2Affine,
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
