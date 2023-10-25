use crate::circuit::config::ShaConfig;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;

pub fn configure_decomposition_gate<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    meta.create_gate("limb decomposition", |meta| {
        let word = meta.query_advice(config.advices[0], Rotation::cur());
        let x = meta.query_advice(config.advices[1], Rotation::cur());
        let y = meta.query_advice(config.advices[2], Rotation::cur());
        let z = meta.query_advice(config.advices[3], Rotation::cur());

        let x_shift = meta.query_fixed(config.fixed[0], Rotation::cur());
        let y_shift = meta.query_fixed(config.fixed[1], Rotation::cur());

        let s = meta.query_selector(config.decomposition_selector());

        vec![s * (word - (x * x_shift + y * y_shift + z))]
    });
}
