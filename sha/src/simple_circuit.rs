use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct FieldConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

pub struct SimpleCircuit<E: MultiMillerLoop> {
    pub a: Value<E::Scalar>,
    pub b: Value<E::Scalar>,
    pub _marker: PhantomData<E>,
}

impl<E: MultiMillerLoop> Default for SimpleCircuit<E> {
    fn default() -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            _marker: PhantomData::default(),
        }
    }
}

impl<E: MultiMillerLoop> Circuit<E> for SimpleCircuit<E> {
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
        let advice = meta.advice_column();
        meta.enable_equality(advice);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let selector = meta.selector();

        meta.create_gate("cross-equality", |vc| {
            let a = vc.query_advice(advice, Rotation::cur());
            let b = vc.query_advice(advice, Rotation::next());

            let a_prime = vc.query_instance(instance, Rotation::cur());
            let b_prime = vc.query_instance(instance, Rotation::next());

            let s = vc.query_selector(selector);

            vec![s.clone() * (a - b_prime), s * (b - a_prime)]
        });

        FieldConfig { advice, instance, selector }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<E::Scalar>,
    ) -> Result<(), Error> {
        let (a, b) = layouter.assign_region(
            || "assign advice",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let a = region.assign_advice(config.advice, 0, self.a)?;
                let b = region.assign_advice(config.advice, 1, self.b)?;
                Ok((a, b))
            },
        )?;

        layouter.constrain_instance(*b.cell(), config.instance, 0);
        layouter.constrain_instance(*a.cell(), config.instance, 1);

        Ok(())
    }
}
