use crate::tables::Limbs;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub struct ShaCircuit<E: MultiMillerLoop, L> {
    pub a: Value<E::Scalar>,
    pub b: Value<E::Scalar>,
    pub c: Value<E::Scalar>,
    pub d: Value<E::Scalar>,
    pub e: Value<E::Scalar>,
    pub f: Value<E::Scalar>,
    pub g: Value<E::Scalar>,
    pub h: Value<E::Scalar>,
    _marker: PhantomData<(E, L)>,
}

impl<E: MultiMillerLoop, L> ShaCircuit<E, L> {
    pub fn new(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32) -> Self {
        Self {
            a: Value::known(E::Scalar::from(a as u64)),
            b: Value::known(E::Scalar::from(b as u64)),
            c: Value::known(E::Scalar::from(c as u64)),
            d: Value::known(E::Scalar::from(d as u64)),
            e: Value::known(E::Scalar::from(e as u64)),
            f: Value::known(E::Scalar::from(f as u64)),
            g: Value::known(E::Scalar::from(g as u64)),
            h: Value::known(E::Scalar::from(h as u64)),
            _marker: PhantomData::default(),
        }
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
            _marker: PhantomData::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShaConfig {
    advices: [Column<Advice>; 4],
    instance: Column<Instance>,
    selectors: [Selector; 4],
    fixed: [Column<Fixed>; 2],
}

impl<E: MultiMillerLoop, L: Limbs> Circuit<E> for ShaCircuit<E, L> {
    type Config = ShaConfig;
    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
        // ================
        // COLUMNS CREATION
        // ================
        let advices = (0..4)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<_>>();
        let instance = meta.instance_column();
        let selectors = (0..4).map(|_| meta.selector()).collect::<Vec<_>>();
        let fixed = (0..2).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        // =============
        // GATE CREATION
        // =============
        meta.create_gate("simple decomposition", |meta| {
            let word = meta.query_advice(advices[0], Rotation::cur());
            let x = meta.query_advice(advices[1], Rotation::cur());
            let y = meta.query_advice(advices[2], Rotation::cur());
            let z = meta.query_advice(advices[3], Rotation::cur());

            let x_shift = meta.query_fixed(fixed[0], Rotation::cur());
            let y_shift = meta.query_fixed(fixed[1], Rotation::cur());

            let s = meta.query_selector(selectors[0]);

            vec![s * (word - (x * x_shift + y * y_shift + z))]
        });

        ShaConfig {
            advices: advices.try_into().unwrap(),
            instance,
            selectors: selectors.try_into().unwrap(),
            fixed: fixed.try_into().unwrap(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<E::Scalar, E = E>,
    ) -> Result<(), Error> {
        // ==========================================================================
        // Assign inputs (a..h) and copy 6 of them right away to the instance column.
        // ==========================================================================
        let cells = layouter.assign_region(
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

        layouter.constrain_instance(*cells[0].cell(), config.instance, 1); // b' = a
        layouter.constrain_instance(*cells[1].cell(), config.instance, 2); // c' = b
        layouter.constrain_instance(*cells[2].cell(), config.instance, 3); // d' = c

        layouter.constrain_instance(*cells[4].cell(), config.instance, 5); // f' = e
        layouter.constrain_instance(*cells[5].cell(), config.instance, 6); // g' = f
        layouter.constrain_instance(*cells[6].cell(), config.instance, 7); // h' = g

        // =========================================
        // Decompose a,b,c,e,f,g into shorter limbs.
        // =========================================
        for (offset, ((word, input_cell), input)) in
            [self.a, self.b, self.c, self.e, self.f, self.g]
                .iter()
                .zip([
                    &cells[0], &cells[1], &cells[2], &cells[4], &cells[5], &cells[6],
                ])
                .zip(["a", "b", "c", "e", "f", "g"])
                .enumerate()
        {
            layouter.assign_region(
                || format!("{input}: limb decomposition"),
                |mut region| {
                    config.selectors[0].enable(&mut region, offset + 2)?;

                    let word_cell = region.assign_advice(config.advices[0], offset + 2, *word)?;
                    region.constrain_equal(word_cell.cell(), input_cell.cell());

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

                    region.assign_advice(config.advices[1], offset + 2, x)?;
                    region.assign_advice(config.advices[2], offset + 2, y)?;
                    region.assign_advice(config.advices[3], offset + 2, z)?;

                    Ok(())
                },
            )?;
        }

        Ok(())
    }
}
