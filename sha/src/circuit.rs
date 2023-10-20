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
    selector: [Selector; 3],
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

        let selector = (0..3).map(|_| meta.selector()).collect::<Vec<_>>();

        // =============
        // GATE CREATION
        // =============
        meta.create_gate("simply copy 6 inputs", |vc| {
            let a = vc.query_advice(advices[0], Rotation::cur());
            let b = vc.query_advice(advices[1], Rotation::cur());
            let c = vc.query_advice(advices[2], Rotation::cur());

            let e = vc.query_advice(advices[0], Rotation::next());
            let f = vc.query_advice(advices[1], Rotation::next());
            let g = vc.query_advice(advices[2], Rotation::next());

            let b_prime = vc.query_advice(advices[0], Rotation(2));
            let c_prime = vc.query_advice(advices[1], Rotation(2));
            let d_prime = vc.query_advice(advices[2], Rotation(2));

            let f_prime = vc.query_advice(advices[0], Rotation(3));
            let g_prime = vc.query_advice(advices[1], Rotation(3));
            let h_prime = vc.query_advice(advices[2], Rotation(3));

            let selector = vc.query_selector(selector[0]);

            [
                selector.clone() * (a - b_prime),
                selector.clone() * (b - c_prime),
                selector.clone() * (c - d_prime),
                selector.clone() * (e - f_prime),
                selector.clone() * (f - g_prime),
                selector * (g - h_prime),
            ]
        });

        ShaConfig {
            advice: advices.try_into().unwrap(),
            instance,
            selector: selector.try_into().unwrap(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<E::Scalar, E = E>,
    ) -> Result<(), Error> {
        todo!()
    }
}
