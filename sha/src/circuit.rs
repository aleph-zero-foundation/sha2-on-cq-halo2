mod config;
mod gates;
mod synthesis;
mod tables;
#[cfg(test)]
mod tests;

use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::pairing::{Engine, MultiMillerLoop},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    circuit::{
        config::ShaConfig,
        gates::configure_addition_gate,
        synthesis::{
            bitwise_choose, bitwise_majority, compose, decompose, finalize_round,
            initial_assignment, register_tables, rotation0, rotation1, BitwiseInput, CelledValue,
            FinalInput, LimbCompositionInput, LimbDecompositionInput, RotationInput,
        },
        tables::{
            configure_choose_table, configure_decomposition_table, configure_majority_table,
            configure_rot0_table, configure_rot1_table, ShaTables,
        },
    },
    tables::Limbs,
};

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

    fn limb_decomposition_inputs<'this, 'cells, 'assign>(
        &'this self,
        row_offset: usize,
        input_cells: &'cells [CelledValue<'assign, E::Scalar>; 8],
    ) -> Vec<LimbDecompositionInput<'assign, 'cells, E::Scalar>> {
        [(0, "a"), (1, "b"), (2, "c"), (4, "e"), (5, "f"), (6, "g")]
            .into_iter()
            .enumerate()
            .map(|(offset, (idx, name))| LimbDecompositionInput {
                row: row_offset + offset,
                source: &input_cells[idx],
                name,
            })
            .collect()
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

        configure_addition_gate(meta, &config);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<E::Scalar, E = E>,
    ) -> Result<(), Error> {
        // =======================
        // Register static tables.
        // =======================
        register_tables(&mut layouter, &self.tables);

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
            .limb_decomposition_inputs(2, &input_cells)
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
        let choose = compose(
            &mut layouter,
            &config,
            LimbCompositionInput {
                row_offset: 15,
                limbs: choose_limbs,
            },
        )?;

        // ==================
        // Compute rotations.
        // ==================
        let rot_0 = rotation0(
            &mut layouter,
            &config,
            RotationInput {
                row_offset: 16,
                input: &input_cells[0],
            },
        )?;
        let rot_1 = rotation1(
            &mut layouter,
            &config,
            RotationInput {
                row_offset: 17,
                input: &input_cells[4],
            },
        )?;

        // ====================
        // Compute temp, e', a'
        // ====================
        finalize_round(
            &mut layouter,
            &config,
            FinalInput {
                row_offset: 18,
                d: &input_cells[3],
                h: &input_cells[7],
                choose: &choose,
                maj: &majority,
                rot0a: &rot_0,
                rot1e: &rot_1,
            },
        )?;

        Ok(())
    }
}
