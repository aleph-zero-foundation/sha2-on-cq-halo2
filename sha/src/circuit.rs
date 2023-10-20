use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ShaConfig {
    advice: [Column<Advice>; 4],
    instance: Column<Instance>,
    selector: [Selector; 2],
}

pub struct ShaCircuit<E: MultiMillerLoop> {
    pub a: Value<E::Scalar>,
    pub b: Value<E::Scalar>,
    pub c: Value<E::Scalar>,
    pub d: Value<E::Scalar>,
    pub e: Value<E::Scalar>,
    pub f: Value<E::Scalar>,
    pub g: Value<E::Scalar>,
    pub h: Value<E::Scalar>,
    _marker: PhantomData<E>,
}

impl<E: MultiMillerLoop> ShaCircuit<E> {
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

impl<E: MultiMillerLoop> Default for ShaCircuit<E> {
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

impl<E: MultiMillerLoop> Circuit<E> for ShaCircuit<E> {
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

        let selector = (0..2).map(|_| meta.selector()).collect::<Vec<_>>();

        // =============
        // GATE CREATION
        // =============

        ShaConfig {
            advice: advices.try_into().unwrap(),
            instance,
            selector: selector.try_into().unwrap(),
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
        let (b_prime, c_prime, d_prime, f_prime, g_prime, h_prime) = layouter.assign_region(
            || "assign inputs",
            |mut region| {
                let a = region.assign_advice(config.advice[0], 0, self.a)?;
                let b = region.assign_advice(config.advice[1], 0, self.b)?;
                let c = region.assign_advice(config.advice[2], 0, self.c)?;
                let _d = region.assign_advice(config.advice[3], 0, self.d)?;

                let e = region.assign_advice(config.advice[0], 1, self.e)?;
                let f = region.assign_advice(config.advice[1], 1, self.f)?;
                let g = region.assign_advice(config.advice[2], 1, self.g)?;
                let _h = region.assign_advice(config.advice[3], 1, self.h)?;

                Ok((a, b, c, e, f, g))
            },
        )?;

        layouter.constrain_instance(*b_prime.cell(), config.instance, 1);
        layouter.constrain_instance(*c_prime.cell(), config.instance, 2);
        layouter.constrain_instance(*d_prime.cell(), config.instance, 3);

        layouter.constrain_instance(*f_prime.cell(), config.instance, 5);
        layouter.constrain_instance(*g_prime.cell(), config.instance, 6);
        layouter.constrain_instance(*h_prime.cell(), config.instance, 7);

        Ok(())
    }
}
