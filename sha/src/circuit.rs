mod config;
mod synthesis;
mod tables;
#[cfg(test)]
mod tests;

use crate::circuit::config::ShaConfig;
use crate::circuit::synthesis::{
    bitwise_choose, bitwise_majority, compose, decompose, initial_assignment, BitwiseInput,
    LimbCompositionInput, LimbDecompositionInput,
};
use crate::circuit::tables::{
    configure_choose_table, configure_decomposition_table, configure_majority_table,
    configure_rot0_table, configure_rot1_table, ShaTables,
};
use crate::tables::Limbs;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{Assigned, Circuit, ConstraintSystem, Error};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct ShaCircuit<E: MultiMillerLoop, L> {
    a: Value<E::Scalar>,
    b: Value<E::Scalar>,
    c: Value<E::Scalar>,
    d: Value<E::Scalar>,
    e: Value<E::Scalar>,
    f: Value<E::Scalar>,
    g: Value<E::Scalar>,
    h: Value<E::Scalar>,

    tables: ShaTables<E>,

    _marker: PhantomData<(E, L)>,
}

impl<E: MultiMillerLoop, L> Default for ShaCircuit<E, L> {
    fn default() -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            c: Value::unknown(),
            d: Value::unknown(),
            e: Value::unknown(),
            f: Value::unknown(),
            g: Value::unknown(),
            h: Value::unknown(),

            tables: ShaTables::default(),

            _marker: PhantomData::default(),
        }
    }
}

impl<E: MultiMillerLoop, L> ShaCircuit<E, L> {
    pub fn new(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
        tables: ShaTables<E>,
    ) -> Self {
        Self {
            a: Value::known(E::Scalar::from(a as u64)),
            b: Value::known(E::Scalar::from(b as u64)),
            c: Value::known(E::Scalar::from(c as u64)),
            d: Value::known(E::Scalar::from(d as u64)),
            e: Value::known(E::Scalar::from(e as u64)),
            f: Value::known(E::Scalar::from(f as u64)),
            g: Value::known(E::Scalar::from(g as u64)),
            h: Value::known(E::Scalar::from(h as u64)),

            tables,

            _marker: PhantomData::default(),
        }
    }

    fn limb_decomposition_inputs(
        &self,
        row_offset: usize,
        input_cells: [AssignedCell<&Assigned<E::Scalar>, E::Scalar>; 8],
    ) -> Vec<LimbDecompositionInput<E::Scalar>> {
        let words = [self.a, self.b, self.c, self.e, self.f, self.g];
        let cells = [
            &input_cells[0],
            &input_cells[1],
            &input_cells[2],
            &input_cells[4],
            &input_cells[5],
            &input_cells[6],
        ];
        let names = ["a", "b", "c", "e", "f", "g"];

        (0..6)
            .map(move |idx| LimbDecompositionInput {
                row: row_offset + idx,
                origin_cell: *cells[idx].cell(),
                source_value: words[idx],
                name: names[idx],
            })
            .collect::<Vec<_>>()
    }
}

impl<E: MultiMillerLoop, L: Limbs> Circuit<E> for ShaCircuit<E, L> {
    type Config = ShaConfig;
    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
        let config = ShaConfig::new(meta);

        configure_decomposition_table(meta, &config);
        configure_majority_table(meta, &config);
        configure_choose_table(meta, &config);
        configure_rot0_table(meta, &config);
        configure_rot1_table(meta, &config);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<E::Scalar, E = E>,
    ) -> Result<(), Error> {
        // ==========================================================================
        // Assign inputs (a..h) and copy 6 of them right away to the instance column.
        // ==========================================================================
        let input_cells = initial_assignment(
            &mut layouter,
            &config,
            [
                self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h,
            ],
        )?;

        // =========================================
        // Decompose a,b,c,e,f,g into shorter limbs.
        // =========================================
        let limb_cells: Vec<_> = self
            .limb_decomposition_inputs(2, input_cells)
            .into_iter()
            .map(|input| decompose::<_, L>(&mut layouter, &config, input))
            .collect::<Result<Vec<_>, _>>()?;

        // =========================
        // Compute bitwise majority.
        // =========================
        let majority_limbs = bitwise_majority(
            &mut layouter,
            &config,
            BitwiseInput {
                row_offset: 8,
                limbs1: &limb_cells[0],
                limbs2: &limb_cells[1],
                limbs3: &limb_cells[2],
            },
        )?;

        // ======================================
        // Combine majorities into a single word.
        // ======================================
        let majority = compose(
            &mut layouter,
            &config,
            LimbCompositionInput {
                row_offset: 11,
                limbs: majority_limbs,
            },
        )?;

        // =======================
        // Compute bitwise choose.
        // =======================
        let choose_limbs = bitwise_choose(
            &mut layouter,
            &config,
            BitwiseInput {
                row_offset: 12,
                limbs1: &limb_cells[3],
                limbs2: &limb_cells[4],
                limbs3: &limb_cells[5],
            },
        )?;

        // ===================================
        // Combine chooses into a single word.
        // ===================================
        let majority = compose(
            &mut layouter,
            &config,
            LimbCompositionInput {
                row_offset: 15,
                limbs: choose_limbs,
            },
        )?;

        Ok(())
    }
}
