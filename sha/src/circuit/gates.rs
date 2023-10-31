use halo2_proofs::{arithmetic::Field, plonk::ConstraintSystem, poly::Rotation};

use crate::circuit::config::ShaConfig;

pub fn configure_addition_gate<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    meta.create_gate("addition", |meta| {
        let selector = meta.query_selector(config.addition_selector());

        let x = meta.query_advice(config.advices[0], Rotation::cur());
        let y = meta.query_advice(config.advices[1], Rotation::cur());
        let z = meta.query_advice(config.advices[2], Rotation::cur());
        let result = meta.query_advice(config.advices[3], Rotation::cur());

        vec![selector * (x + y + z - result)]
    });
}
