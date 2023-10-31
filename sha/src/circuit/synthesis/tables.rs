use halo2_proofs::{
    circuit::Layouter,
    halo2curves::pairing::{Engine, MultiMillerLoop},
    plonk::static_lookup::{StaticTable, StaticTableId},
};

use crate::circuit::tables::{columns::*, ShaTables};

pub fn register_tables<E: MultiMillerLoop>(
    layouter: &mut impl Layouter<<E as Engine>::Scalar, E = E>,
    tables: &ShaTables<E>,
) {
    register(
        layouter,
        [
            (DECOMPOSITION_X_COLUMN, &tables.decomposition.decomp_x),
            (DECOMPOSITION_Y_COLUMN, &tables.decomposition.decomp_y),
            (DECOMPOSITION_Z_COLUMN, &tables.decomposition.decomp_z),
            (DECOMPOSITION_RESULT_COLUMN, &tables.decomposition.decomp),
            (BITWISE_X_COLUMN, &tables.bitwise.bitwise_x),
            (BITWISE_Y_COLUMN, &tables.bitwise.bitwise_y),
            (BITWISE_Z_COLUMN, &tables.bitwise.bitwise_z),
            (BITWISE_MAJORITY_COLUMN, &tables.bitwise.maj),
            (BITWISE_CHOOSE_COLUMN, &tables.bitwise.choose),
            (ROTATION_INPUT_COLUMN, &tables.rotation.rot_input),
            (ROTATION_0_COLUMN, &tables.rotation.rot0),
            (ROTATION_1_COLUMN, &tables.rotation.rot1),
        ],
    );
}

fn register<E: MultiMillerLoop, I: Iterator<Item = (&'static str, &StaticTable<E>)>>(
    layouter: &mut impl Layouter<<E as Engine>::Scalar, E = E>,
    tables: I,
) {
    for (id, table) in tables {
        layouter.register_static_table(StaticTableId(id.into()), table.clone());
    }
}
