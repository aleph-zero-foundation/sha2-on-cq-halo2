use crate::circuit::config::ShaConfig;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::pairing::{MultiMillerLoop};
use halo2_proofs::plonk::static_lookup::{StaticTable, StaticTableId};
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;

pub struct ShaTables<E: MultiMillerLoop> {
    x: StaticTable<E>,
    y: StaticTable<E>,
    z: StaticTable<E>,
    maj: StaticTable<E>,
}

impl<E: MultiMillerLoop> Default for ShaTables<E> {
    fn default() -> Self {
        Self {
            x: StaticTable {
                opened: None,
                committed: None,
            },
            y: StaticTable {
                opened: None,
                committed: None,
            },
            z: StaticTable {
                opened: None,
                committed: None,
            },
            maj: StaticTable {
                opened: None,
                committed: None,
            },
        }
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
