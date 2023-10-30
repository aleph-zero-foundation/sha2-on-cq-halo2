//! Simple circuit example:
//!     - 2 private inputs (advices): a, b
//!     - 2 public inputs (instances): a', b'
//!
//! Represented relation:
//!     - a = b'
//!     - b = a'
//!
//! For this, it is enough to have just two columns (one for advices, one for instances). That way
//! we will need 2 rows. A cost for that is a need for a selector, which will be used to trigger
//! 'cross-equality' gate only once.

use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct Config {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

pub struct SimpleCircuit<E: MultiMillerLoop> {
    pub a: Value<E::Scalar>,
    pub b: Value<E::Scalar>,
    pub _marker: PhantomData<E>,
}

impl<E: MultiMillerLoop> SimpleCircuit<E> {
    pub fn new(a: u64, b: u64) -> Self {
        Self {
            a: Value::known(E::Scalar::from(a)),
            b: Value::known(E::Scalar::from(b)),
            _marker: PhantomData::default(),
        }
    }
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
    type Config = Config;
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

        Config {
            advice,
            instance,
            selector,
        }
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

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr},
    };

    use crate::simple_circuit::SimpleCircuit;

    #[test]
    fn test_positive_case() {
        MockProver::run(
            4,
            &SimpleCircuit::<Bn256>::new(1, 2),
            vec![vec![Fr::from(2), Fr::from(1)]],
        )
        .expect("proving should not fail")
        .assert_satisfied();
    }

    #[test]
    fn test_incorrect_input() {
        MockProver::run(
            4,
            &SimpleCircuit::<Bn256>::new(1, 2),
            vec![vec![Fr::from(1), Fr::from(2)]],
        )
        .expect("proving should not fail")
        .verify()
        .unwrap_err();
    }
}
