use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::Error,
};

use crate::circuit::{config::ShaConfig, synthesis::CelledValue};

pub struct FinalInput<'assign, 'cell, F: Field> {
    pub row_offset: usize,

    pub d: &'cell CelledValue<'assign, F>,
    pub h: &'cell CelledValue<'assign, F>,
    pub choose: &'cell CelledValue<'assign, F>,
    pub maj: &'cell CelledValue<'assign, F>,
    pub rot0a: &'cell CelledValue<'assign, F>,
    pub rot1e: &'cell CelledValue<'assign, F>,
}

pub fn finalize_round<E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: FinalInput<E::Scalar>,
) -> Result<(), Error> {
    let temp = row(layouter, config, "compute temp", input.row_offset, &[
        input.h,
        input.rot1e,
        input.choose,
    ])?;

    let e_prime = row(layouter, config, "compute e'", input.row_offset + 1, &[
        input.d,
        &temp,
    ])?;
    layouter.constrain_instance(*e_prime.cell.cell(), config.instance, 4);

    let a_prime = row(layouter, config, "compute a'", input.row_offset + 2, &[
        input.maj,
        input.rot0a,
        &temp,
    ])?;
    layouter.constrain_instance(*a_prime.cell.cell(), config.instance, 0);

    Ok(())
}

fn row<'assign, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    row_title: &'static str,
    row_offset: usize,
    summands: &[&CelledValue<'assign, E::Scalar>],
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || row_title,
        |mut region| {
            config.addition_selector().enable(&mut region, 0)?;

            for (idx, summand) in summands.iter().enumerate() {
                let cell = region.assign_advice(config.advices[idx], row_offset, summand.value)?;
                region.constrain_equal(summand.cell.cell(), cell.cell());
            }

            let sum = summands
                .iter()
                .fold(Value::known(Default::default()), |acc, summand| {
                    acc + summand.value
                });
            let sum_cell = region.assign_advice(config.advices[3], row_offset, sum)?;

            Ok(CelledValue {
                cell: sum_cell,
                value: sum,
            })
        },
    )
}
