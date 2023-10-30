use halo2_proofs::{
    arithmetic::{Field},
    circuit::{Layouter, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::{Error},
};

use crate::{
    circuit::{
        config::ShaConfig,
        synthesis::{CelledValue, LimbDecomposition},
    },
    tables::Limbs,
};

pub struct LimbCompositionInput<'assign, F: Field> {
    pub row_offset: usize,
    pub limbs: LimbDecomposition<'assign, F>,
}

pub fn compose<'assign, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: LimbCompositionInput<E::Scalar>,
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || "compose from limbs",
        |mut region| {
            config
                .decomposition_selector()
                .enable(&mut region, input.row_offset)?;

            let x_cell =
                region.assign_advice(config.advices[0], input.row_offset, input.limbs.x.value)?;
            let y_cell =
                region.assign_advice(config.advices[1], input.row_offset, input.limbs.y.value)?;
            let z_cell =
                region.assign_advice(config.advices[2], input.row_offset, input.limbs.z.value)?;

            region.constrain_equal(input.limbs.x.cell.cell(), x_cell.cell());
            region.constrain_equal(input.limbs.y.cell.cell(), y_cell.cell());
            region.constrain_equal(input.limbs.z.cell.cell(), z_cell.cell());

            let composition = Value::known(Default::default()); // todo compute real composition
            let composition_cell =
                region.assign_advice(config.advices[3], input.row_offset, composition)?;

            Ok(CelledValue {
                value: composition,
                cell: composition_cell,
            })
        },
    )
}
