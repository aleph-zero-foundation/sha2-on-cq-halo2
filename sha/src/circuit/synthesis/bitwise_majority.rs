use crate::circuit::config::ShaConfig;
use crate::circuit::synthesis::LimbDecompositionOutput;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::Error;

pub struct BitwiseMajorityInput<'assign, 'limb, F: Field> {
    pub row_offset: usize,
    pub a_limbs: &'limb LimbDecompositionOutput<'assign, F>,
    pub b_limbs: &'limb LimbDecompositionOutput<'assign, F>,
    pub c_limbs: &'limb LimbDecompositionOutput<'assign, F>,
}

pub type BitwiseMajorityOutput<'assign, F> = LimbDecompositionOutput<'assign, F>;

pub fn bitwise_majority<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: BitwiseMajorityInput<'assign, 'limb, E::Scalar>,
) -> Result<BitwiseMajorityOutput<'assign, E::Scalar>, Error> {
    let (x_cell, x_value) = layouter.assign_region(
        || "majority: x",
        |mut region| {
            config
                .majority_selector()
                .enable(&mut region, input.row_offset)?;

            let w0 =
                region.assign_advice(config.advices[0], input.row_offset, input.a_limbs.x_value)?;
            let w1 =
                region.assign_advice(config.advices[1], input.row_offset, input.b_limbs.x_value)?;
            let w2 =
                region.assign_advice(config.advices[2], input.row_offset, input.c_limbs.x_value)?;

            region.constrain_equal(w0.cell(), input.a_limbs.x_cell.cell());
            region.constrain_equal(w1.cell(), input.b_limbs.x_cell.cell());
            region.constrain_equal(w2.cell(), input.c_limbs.x_cell.cell());

            let w_maj = region.assign_advice(
                config.advices[3],
                input.row_offset,
                Value::known(E::Scalar::default()),
            )?;

            Ok((w_maj, Value::known(E::Scalar::default())))
        },
    )?;

    Ok(LimbDecompositionOutput {
        x_cell: x_cell.clone(),
        y_cell: x_cell.clone(),
        z_cell: x_cell,
        x_value,
        y_value: x_value,
        z_value: x_value,
    })
}
