use halo2_proofs::halo2curves::pairing::{Engine, MultiMillerLoop};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed, Instance, Selector};

const ADVICE_NUM: usize = 4;
const SELECTOR_NUM: usize = 3;
const FIXED_NUM: usize = 2;

#[derive(Clone, Debug)]
pub struct ShaConfig {
    pub advices: [Column<Advice>; ADVICE_NUM],
    pub instance: Column<Instance>,
    pub selectors: [Selector; SELECTOR_NUM],
    pub fixed: [Column<Fixed>; FIXED_NUM],
}

impl ShaConfig {
    pub fn new<E: MultiMillerLoop>(meta: &mut ConstraintSystem<<E as Engine>::Scalar>) -> Self {
        let advices = Self::create_columns::<ADVICE_NUM, _, _>(|| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });
        let instance = meta.instance_column();
        let selectors = Self::create_columns::<SELECTOR_NUM, _, _>(|| meta.selector());
        let fixed = Self::create_columns::<FIXED_NUM, _, _>(|| meta.fixed_column());

        Self {
            advices: advices.try_into().unwrap(),
            instance,
            selectors,
            fixed: fixed.try_into().unwrap(),
        }
    }

    fn create_columns<const NUMBER: usize, C, F: FnMut() -> C>(mut creator: F) -> [C; NUMBER] {
        (0..NUMBER)
            .map(|_| creator())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| ())
            .unwrap()
    }

    pub fn decomposition_selector(&self) -> Selector {
        self.selectors[0]
    }

    pub fn majority_selector(&self) -> Selector {
        self.selectors[1]
    }

    pub fn choose_selector(&self) -> Selector {
        self.selectors[2]
    }
}
