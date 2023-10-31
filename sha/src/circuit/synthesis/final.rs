use halo2_proofs::{
    arithmetic::Field, circuit::Layouter, halo2curves::pairing::MultiMillerLoop, plonk::Error,
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

pub fn finalize_round<'assign, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: FinalInput<E::Scalar>,
) -> Result<(), Error> {
    let temp = layouter.assign_region(
        || "compute temp",
        |mut region| {
            config.addition_selector().enable(&mut region, input.row_offset)?;

            let h_cell =
                region.assign_advice(config.advices[0], input.row_offset, input.h.value)?;
            region.constrain_equal(input.h.cell.cell(), h_cell.cell());

            let rot1e_cell =
                region.assign_advice(config.advices[1], input.row_offset, input.rot1e.value)?;
            region.constrain_equal(input.rot1e.cell.cell(), rot1e_cell.cell());

            let ch_cell =
                region.assign_advice(config.advices[2], input.row_offset, input.choose.value)?;
            region.constrain_equal(input.choose.cell.cell(), ch_cell.cell());

            let temp_value = input.h.value + input.rot1e.value + input.choose.value;
            let temp_cell =
                region.assign_advice(config.advices[3], input.row_offset, temp_value)?;

            Ok(CelledValue {
                value: temp_value,
                cell: temp_cell,
            })
        },
    )?;

    let e_prime = layouter.assign_region(
        || "compute e'",
        |mut region| {
            config.addition_selector().enable(&mut region, input.row_offset + 1)?;

            let temp_cell =
                region.assign_advice(config.advices[0], input.row_offset + 1, temp.value)?;
            region.constrain_equal(temp.cell.cell(), temp_cell.cell());

            let d_cell =
                region.assign_advice(config.advices[1], input.row_offset + 1, input.d.value)?;
            region.constrain_equal(input.d.cell.cell(), d_cell.cell());

            let e_prime_value = temp.value + input.d.value;
            let e_prime_cell =
                region.assign_advice(config.advices[3], input.row_offset + 1, e_prime_value)?;

            Ok(CelledValue {
                value: e_prime_value,
                cell: e_prime_cell,
            })
        },
    )?;

    layouter.constrain_instance(*e_prime.cell.cell(), config.instance, 4);

    let a_prime = layouter.assign_region(
        || "compute a'",
        |mut region| {
            config.addition_selector().enable(&mut region, input.row_offset + 2)?;

            let temp_cell =
                region.assign_advice(config.advices[0], input.row_offset + 2, temp.value)?;
            region.constrain_equal(temp.cell.cell(), temp_cell.cell());

            let rot0a_cell =
                region.assign_advice(config.advices[1], input.row_offset + 2, input.rot0a.value)?;
            region.constrain_equal(input.rot0a.cell.cell(), rot0a_cell.cell());

            let maj_cell =
                region.assign_advice(config.advices[2], input.row_offset + 2, input.maj.value)?;
            region.constrain_equal(input.maj.cell.cell(), maj_cell.cell());

            let a_prime_value = temp.value + input.rot0a.value + input.maj.value;
            let a_prime_cell =
                region.assign_advice(config.advices[3], input.row_offset + 2, a_prime_value)?;

            Ok(CelledValue {
                value: a_prime_value,
                cell: a_prime_cell,
            })
        },
    )?;

    layouter.constrain_instance(*a_prime.cell.cell(), config.instance, 0);

    Ok(())
}
