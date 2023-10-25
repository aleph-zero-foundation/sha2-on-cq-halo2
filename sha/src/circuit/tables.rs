use crate::circuit::config::ShaConfig;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::static_lookup::{StaticTable, StaticTableId};
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;

pub struct ShaTables<E: MultiMillerLoop> {
    pub x: StaticTable<E>,
    pub y: StaticTable<E>,
    pub z: StaticTable<E>,
    pub maj: StaticTable<E>,
}

impl<E: MultiMillerLoop> ShaTables<E> {
    pub fn new(
        x: StaticTable<E>,
        y: StaticTable<E>,
        z: StaticTable<E>,
        maj: StaticTable<E>,
    ) -> Self {
        Self { x, y, z, maj }
    }
}

impl<E: MultiMillerLoop> Default for ShaTables<E> {
    fn default() -> Self {
        let empty = StaticTable {
            opened: None,
            committed: None,
        };

        Self::new(empty.clone(), empty.clone(), empty.clone(), empty.clone())
    }
}

pub fn configure_majority_table<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    meta.lookup_static("majority", |meta| {
        let maj_selector = meta.query_selector(config.majority_selector());

        [(0, "x"), (1, "y"), (2, "z"), (3, "maj")]
            .map(|(advice_idx, col_name)| {
                (
                    maj_selector.clone()
                        * meta.query_advice(config.advices[advice_idx], Rotation::cur()),
                    StaticTableId(col_name.into()),
                )
            })
            .to_vec()
    });
}
