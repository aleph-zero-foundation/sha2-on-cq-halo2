use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::{Error},
};

use crate::circuit::{config::ShaConfig, synthesis::CelledValue};

const LAYOUT_WIDTH: usize = 4;

pub type InitialAssignmentInput<F> = [Value<F>; 8];
pub type InitialAssignmentOutput<'assign, F> = [CelledValue<'assign, F>; 8];

pub fn initial_assignment<'assign, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: InitialAssignmentInput<E::Scalar>,
) -> Result<InitialAssignmentOutput<'assign, E::Scalar>, Error> {
    let input_cells = layouter.assign_region(
        || "assign inputs",
        |mut region| {
            input
                .iter()
                .enumerate()
                .map(|(idx, value)| (idx % LAYOUT_WIDTH, idx / LAYOUT_WIDTH, value))
                .map(|(column, row, value)| {
                    region
                        .assign_advice(config.advices[column], row, *value)
                        .map(|cell| CelledValue {
                            cell,
                            value: *value,
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        },
    )?;

    layouter.constrain_instance(*input_cells[0].cell.cell(), config.instance, 1); // b' = a
    layouter.constrain_instance(*input_cells[1].cell.cell(), config.instance, 2); // c' = b
    layouter.constrain_instance(*input_cells[2].cell.cell(), config.instance, 3); // d' = c

    layouter.constrain_instance(*input_cells[4].cell.cell(), config.instance, 5); // f' = e
    layouter.constrain_instance(*input_cells[5].cell.cell(), config.instance, 6); // g' = f
    layouter.constrain_instance(*input_cells[6].cell.cell(), config.instance, 7); // h' = g

    Ok(input_cells.try_into().map_err(|_| ()).unwrap())
}
