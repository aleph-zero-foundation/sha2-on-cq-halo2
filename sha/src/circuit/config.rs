use halo2_proofs::{
    arithmetic::Field,
    plonk::{Advice, Column, ConstraintSystem, Instance, Selector},
};

pub const ADVICE_NUM: usize = 4;
pub const LOOKUP_SELECTOR_NUM: usize = 5;

#[derive(Clone, Debug)]
pub struct ShaConfig {
    pub advices: [Column<Advice>; ADVICE_NUM],
    pub instance: Column<Instance>,
    pub lookup_selectors: [Selector; LOOKUP_SELECTOR_NUM],
}

impl ShaConfig {
    pub fn new<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let advices = Self::create_columns::<ADVICE_NUM, _, _>(|| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let lookup_selectors =
            Self::create_columns::<LOOKUP_SELECTOR_NUM, _, _>(|| meta.complex_selector());

        Self {
            advices,
            instance,
            lookup_selectors,
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
        self.lookup_selectors[0]
    }

    pub fn majority_selector(&self) -> Selector {
        self.lookup_selectors[1]
    }

    pub fn choose_selector(&self) -> Selector {
        self.lookup_selectors[2]
    }
    pub fn rot0_selector(&self) -> Selector {
        self.lookup_selectors[3]
    }

    pub fn rot1_selector(&self) -> Selector {
        self.lookup_selectors[4]
    }
}
