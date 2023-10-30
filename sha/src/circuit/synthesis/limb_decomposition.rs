use crate::circuit::config::ShaConfig;
use crate::tables::Limbs;
use halo2_proofs::arithmetic::{Field, FieldExt};
use halo2_proofs::circuit::{AssignedCell, Cell, Layouter, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{Assigned, Error};
use crate::circuit::synthesis::LimbDecomposition;

pub struct LimbDecompositionInput<F: Field> {
    /// The row in which the decomposition gate happening.
    pub row: usize,
    /// The cell from which the word (to be decomposed) should 'copied' from.
    pub origin_cell: Cell,
    /// The value of the word to be decomposed.
    pub source_value: Value<F>,
    /// Identifier for the gate.
    pub name: &'static str,
}

pub fn decompose<'assign, E: MultiMillerLoop, L: Limbs>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: LimbDecompositionInput<E::Scalar>,
) -> Result<LimbDecomposition<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || format!("{}: limb decomposition", input.name),
        |mut region| {
            // Enable this gate with corresponding selector. This will constrain the values to be
            // computed correctly (by a lookup).
            config
                .decomposition_selector()
                .enable(&mut region, input.row)?;

            // Assign value to the word cell.
            let word = input.source_value;
            let word_cell = region.assign_advice(config.advices[0], input.row, word)?;

            // Ensure that the word is correctly copied from the original cell.
            region.constrain_equal(word_cell.cell(), &input.origin_cell);

            // Compute limbs.
            let shift = L::SECOND_LIMB_LEN;
            let x = word
                .map(|w| w.get_lower_128() >> (shift + shift))
                .map(E::Scalar::from_u128);
            let y = word
                .map(|w| (w.get_lower_128() >> shift) % (1 << shift))
                .map(E::Scalar::from_u128);
            let z = word
                .map(|w| w.get_lower_128() % (1 << shift))
                .map(E::Scalar::from_u128);

            // Assign limb values.
            let x_cell = region.assign_advice(config.advices[1], input.row, x)?;
            let y_cell = region.assign_advice(config.advices[2], input.row, y)?;
            let z_cell = region.assign_advice(config.advices[3], input.row, z)?;

            Ok(LimbDecomposition {
                x_cell,
                y_cell,
                z_cell,
                x_value: x,
                y_value: y,
                z_value: z,
            })
        },
    )
}
