use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::{Error, Selector},
};

use crate::circuit::{config::ShaConfig, synthesis::CelledValue};

pub struct RotationInput<'assign, 'input, F: Field> {
    pub input: &'input CelledValue<'assign, F>,
    pub row_offset: usize,
}

pub fn rotation0<'assign, 'input, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: RotationInput<'assign, 'input, E::Scalar>,
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    rotation(layouter, config, RotationType::Zero, input)
}

pub fn rotation1<'assign, 'input, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: RotationInput<'assign, 'input, E::Scalar>,
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    rotation(layouter, config, RotationType::One, input)
}

fn rotation<'assign, 'input, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    rotation_type: RotationType,
    input: RotationInput<'assign, 'input, E::Scalar>,
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || rotation_type.region_name(),
        |mut region| {
            rotation_type
                .selector(config)
                .enable(&mut region, input.row_offset)?;

            let to_rotate =
                region.assign_advice(config.advices[0], input.row_offset, input.input.value)?;
            region.constrain_equal(to_rotate.cell(), input.input.cell.cell());

            let rotated_value = Value::known(Default::default()); // todo compute true rotation
            let rotated =
                region.assign_advice(config.advices[1], input.row_offset, rotated_value)?;

            Ok(CelledValue {
                cell: rotated,
                value: rotated_value,
            })
        },
    )
}

#[derive(Clone, Copy)]
enum RotationType {
    Zero,
    One,
}

impl RotationType {
    pub fn region_name(&self) -> &'static str {
        match self {
            RotationType::Zero => "rotation 0",
            RotationType::One => "rotation 1",
        }
    }

    pub fn selector(&self, config: &ShaConfig) -> Selector {
        match self {
            RotationType::Zero => config.rot0_selector(),
            RotationType::One => config.rot1_selector(),
        }
    }
}
