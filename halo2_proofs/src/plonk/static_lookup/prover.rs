use ff::Field;
use halo2curves::{pairing::MultiMillerLoop, serde::SerdeObject};

use crate::plonk::ProvingKey;
use std::fmt::Debug;

use crate::plonk::Error;

pub struct Committed<E: MultiMillerLoop> {
    lhs: E::G1Affine,
}

impl<F: Field> super::Argument<F> {
    pub fn commit<E>(&self, pk: ProvingKey<E>) -> Result<Committed<E>, Error>
    where
        E: MultiMillerLoop + Debug,
        E::G1Affine: SerdeObject,
        E::G2Affine: SerdeObject,
    {
        let rhs = pk.static_table_mapping.get(&self.table_id);

        todo!();
    }
}
