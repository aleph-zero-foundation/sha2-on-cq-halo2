use std::marker::PhantomData;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug)]
pub struct FieldConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
}

pub struct SimpleCircuit<E: MultiMillerLoop> {
    pub a: Value<E::Scalar>,
    pub b: Value<E::Scalar>,
    pub _marker: PhantomData<E>
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
        let instance = meta.instance_column();

        meta.create_gate("cross-equality", |vc| {
            let a = vc.query_advice(advice, Rotation::cur());
            let b = vc.query_advice(advice, Rotation::next());

            let a_prime = vc.query_instance(instance, Rotation::cur());
            let b_prime = vc.query_instance(instance, Rotation::next());

            vec![
                a - b_prime,
                b - a_prime,
            ]
        });

        FieldConfig {
            advice,
            instance,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<E::Scalar>) -> Result<(), Error> {
        let _ = layouter.assign_region(||"private input", |mut region| {
            let a = region.assign_advice(config.advice,0, self.a)?;
            let b = region.assign_advice(config.advice,1, self.b)?;
            Ok((a, b))
        })?;

        let (a_prime, b_prime) = layouter.assign_region(||"instance input", |mut region| {
            let a = region.assign_advice_from_instance(||"a'", config.instance,0, config.advice, 2)?;
            let b = region.assign_advice_from_instance(||"b'", config.instance,1, config.advice, 3)?;
            Ok((a, b))
        })?;

        layouter.constrain_instance(a_prime.cell().clone(), config.instance, 0);
        layouter.constrain_instance(b_prime.cell().clone(), config.instance, 1);

        Ok(())
    }
}
