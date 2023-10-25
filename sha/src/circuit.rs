mod config;
mod gates;
mod synthesis;
mod tables;
#[cfg(test)]
mod tests;

use crate::circuit::config::ShaConfig;
use crate::circuit::gates::configure_decomposition_gate;
use crate::circuit::synthesis::{decompose, LimbDecompositionInput};
use crate::circuit::tables::{configure_majority_table, ShaTables};
use crate::tables::Limbs;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{Assigned, Circuit, ConstraintSystem, Error};
use std::marker::PhantomData;

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

        (0..6).map(move |idx| LimbDecompositionInput {
            row: row_offset + idx,
            origin_cell: *cells[idx].cell(),
            source_value: words[idx],
            name: names[idx],
        }).collect::<Vec<_>>()
    }
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

impl<E: MultiMillerLoop, L: Limbs> Circuit<E> for ShaCircuit<E, L> {
    type Config = ShaConfig;
    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
        let config = ShaConfig::new(meta);

        configure_majority_table(meta, &config);
        configure_decomposition_gate(meta, &config);

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
        let input_cells = layouter.assign_region(
            || "assign inputs",
            |mut region| {
                let a = region.assign_advice(config.advices[0], 0, self.a)?;
                let b = region.assign_advice(config.advices[1], 0, self.b)?;
                let c = region.assign_advice(config.advices[2], 0, self.c)?;
                let d = region.assign_advice(config.advices[3], 0, self.d)?;

                let e = region.assign_advice(config.advices[0], 1, self.e)?;
                let f = region.assign_advice(config.advices[1], 1, self.f)?;
                let g = region.assign_advice(config.advices[2], 1, self.g)?;
                let h = region.assign_advice(config.advices[3], 1, self.h)?;

                Ok([a, b, c, d, e, f, g, h])
            },
        )?;

        layouter.constrain_instance(*input_cells[0].cell(), config.instance, 1); // b' = a
        layouter.constrain_instance(*input_cells[1].cell(), config.instance, 2); // c' = b
        layouter.constrain_instance(*input_cells[2].cell(), config.instance, 3); // d' = c

        layouter.constrain_instance(*input_cells[4].cell(), config.instance, 5); // f' = e
        layouter.constrain_instance(*input_cells[5].cell(), config.instance, 6); // g' = f
        layouter.constrain_instance(*input_cells[6].cell(), config.instance, 7); // h' = g

        // =========================================
        // Decompose a,b,c,e,f,g into shorter limbs.
        // =========================================
        let limb_cells: Vec<_> = self
            .limb_decomposition_inputs(2, input_cells)
            .into_iter()
            .map(|input| decompose::<_, L>(&mut layouter, &config, input))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        // =========================
        // Compute bitwise majority.
        // =========================

        Ok(())
    }
}
