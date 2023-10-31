use halo2_proofs::{
    circuit::Layouter,
    halo2curves::pairing::{Engine, MultiMillerLoop},
    plonk::{static_lookup::StaticTableId, Error},
};

use crate::circuit::tables::{
    columns::*, BitwiseTables, DecompositionTables, RotationTables, ShaTables,
};

pub fn register_tables<E: MultiMillerLoop>(
    layouter: &mut impl Layouter<<E as Engine>::Scalar, E = E>,
    tables: &ShaTables<E>,
) {
    register_decomposition(layouter, &tables.decomposition);
    register_bitwise(layouter, &tables.bitwise);
    register_rotation(layouter, &tables.rotation);
}

fn register_decomposition<E: MultiMillerLoop>(
    layouter: &mut impl Layouter<<E as Engine>::Scalar, E = E>,
    tables: &DecompositionTables<E>,
) {
    layouter.register_static_table(
        StaticTableId(DECOMPOSITION_X_COLUMN.into()),
        tables.decomp_x.clone(),
    );
    layouter.register_static_table(
        StaticTableId(DECOMPOSITION_Y_COLUMN.into()),
        tables.decomp_y.clone(),
    );
    layouter.register_static_table(
        StaticTableId(DECOMPOSITION_Z_COLUMN.into()),
        tables.decomp_z.clone(),
    );
    layouter.register_static_table(
        StaticTableId(DECOMPOSITION_RESULT_COLUMN.into()),
        tables.decomp.clone(),
    );
}

fn register_bitwise<E: MultiMillerLoop>(
    layouter: &mut impl Layouter<<E as Engine>::Scalar, E = E>,
    tables: &BitwiseTables<E>,
) {
    layouter.register_static_table(
        StaticTableId(BITWISE_X_COLUMN.into()),
        tables.bitwise_x.clone(),
    );
    layouter.register_static_table(
        StaticTableId(BITWISE_Y_COLUMN.into()),
        tables.bitwise_y.clone(),
    );
    layouter.register_static_table(
        StaticTableId(BITWISE_Z_COLUMN.into()),
        tables.bitwise_z.clone(),
    );
    layouter.register_static_table(
        StaticTableId(BITWISE_MAJORITY_COLUMN.into()),
        tables.maj.clone(),
    );
    layouter.register_static_table(
        StaticTableId(BITWISE_CHOOSE_COLUMN.into()),
        tables.choose.clone(),
    );
}

fn register_rotation<E: MultiMillerLoop>(
    layouter: &mut impl Layouter<<E as Engine>::Scalar, E = E>,
    tables: &RotationTables<E>,
) {
    layouter.register_static_table(
        StaticTableId(ROTATION_INPUT_COLUMN.into()),
        tables.rot_input.clone(),
    );
    layouter.register_static_table(StaticTableId(ROTATION_0_COLUMN.into()), tables.rot0.clone());
    layouter.register_static_table(StaticTableId(ROTATION_1_COLUMN.into()), tables.rot1.clone());
}
