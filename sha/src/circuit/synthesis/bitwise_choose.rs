use crate::circuit::config::ShaConfig;
use crate::circuit::synthesis::{BitwiseInput, BitwiseOutput, CelledValue, LimbDecomposition};
use halo2_proofs::circuit::{Cell, Layouter, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::Error;

pub fn bitwise_choose<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: BitwiseInput<'assign, 'limb, E::Scalar>,
) -> Result<BitwiseOutput<'assign, E::Scalar>, Error> {
    let x = bitwise_choose_row(
        layouter,
        config,
        input.row_offset,
        "bitwise choose: x",
        input.x_values(),
        input.x_cells(),
    )?;
    let y = bitwise_choose_row(
        layouter,
        config,
        input.row_offset + 1,
        "bitwise choose: y",
        input.y_values(),
        input.y_cells(),
    )?;
    let z = bitwise_choose_row(
        layouter,
        config,
        input.row_offset + 2,
        "bitwise choose: z",
        input.z_values(),
        input.z_cells(),
    )?;

    Ok(LimbDecomposition { x, y, z })
}

fn bitwise_choose_row<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    row_offset: usize,
    region_name: &str,
    values: [Value<E::Scalar>; 3],
    cells: [&'limb Cell; 3],
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || region_name,
        |mut region| {
            config.choose_selector().enable(&mut region, row_offset)?;

            let w0 = region.assign_advice(config.advices[0], row_offset, values[0])?;
            let w1 = region.assign_advice(config.advices[1], row_offset, values[1])?;
            let w2 = region.assign_advice(config.advices[2], row_offset, values[2])?;

            region.constrain_equal(w0.cell(), cells[0]);
            region.constrain_equal(w1.cell(), cells[1]);
            region.constrain_equal(w2.cell(), cells[2]);

            let value = Value::known(E::Scalar::default()); // todo compute true choose
            let w_ch = region.assign_advice(config.advices[3], row_offset, value)?;

            Ok(CelledValue { cell: w_ch, value })
        },
    )
}
