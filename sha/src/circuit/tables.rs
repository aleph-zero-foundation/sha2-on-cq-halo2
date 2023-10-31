use halo2_proofs::{
    arithmetic::Field,
    halo2curves::pairing::MultiMillerLoop,
    plonk::{
        static_lookup::{StaticTable, StaticTableId},
        ConstraintSystem, Selector,
    },
    poly::Rotation,
};

use crate::circuit::{config::ShaConfig, tables::columns::*};

pub mod columns {
    pub const DECOMPOSITION_X_COLUMN: &str = "decomposition_x";
    pub const DECOMPOSITION_Y_COLUMN: &str = "decomposition_y";
    pub const DECOMPOSITION_Z_COLUMN: &str = "decomposition_z";
    pub const DECOMPOSITION_RESULT_COLUMN: &str = "decomposition";
    pub const BITWISE_X_COLUMN: &str = "bitwise_x";
    pub const BITWISE_Y_COLUMN: &str = "bitwise_y";
    pub const BITWISE_Z_COLUMN: &str = "bitwise_z";
    pub const BITWISE_MAJORITY_COLUMN: &str = "majority";
    pub const BITWISE_CHOOSE_COLUMN: &str = "choose";
    pub const ROTATION_INPUT_COLUMN: &str = "rotation_input";
    pub const ROTATION_0_COLUMN: &str = "rotation0";
    pub const ROTATION_1_COLUMN: &str = "rotation1";
}

#[derive(Debug, Clone, Default)]
pub struct DecompositionTables<E: MultiMillerLoop> {
    pub decomp_x: StaticTable<E>,
    pub decomp_y: StaticTable<E>,
    pub decomp_z: StaticTable<E>,
    pub decomp: StaticTable<E>,
}

#[derive(Debug, Clone, Default)]
pub struct BitwiseTables<E: MultiMillerLoop> {
    pub bitwise_x: StaticTable<E>,
    pub bitwise_y: StaticTable<E>,
    pub bitwise_z: StaticTable<E>,
    pub maj: StaticTable<E>,
    pub choose: StaticTable<E>,
}

#[derive(Debug, Clone, Default)]
pub struct RotationTables<E: MultiMillerLoop> {
    pub rot_input: StaticTable<E>,
    pub rot0: StaticTable<E>,
    pub rot1: StaticTable<E>,
}

#[derive(Debug, Clone, Default)]
pub struct ShaTables<E: MultiMillerLoop> {
    pub decomposition: DecompositionTables<E>,
    pub bitwise: BitwiseTables<E>,
    pub rotation: RotationTables<E>,
}

impl<E: MultiMillerLoop> ShaTables<E> {
    pub fn new(
        decomposition: DecompositionTables<E>,
        bitwise: BitwiseTables<E>,
        rotation: RotationTables<E>,
    ) -> Self {
        Self {
            decomposition,
            bitwise,
            rotation,
        }
    }
}

#[derive(Copy, Clone)]
enum TableType {
    Decomposition,
    BitwiseMajority,
    BitwiseChoose,
    Rotation0,
    Rotation1,
}

impl TableType {
    pub fn selector(self, config: &ShaConfig) -> Selector {
        match self {
            TableType::Decomposition => config.decomposition_selector(),
            TableType::BitwiseMajority => config.majority_selector(),
            TableType::BitwiseChoose => config.choose_selector(),
            TableType::Rotation0 => config.rot0_selector(),
            TableType::Rotation1 => config.rot1_selector(),
        }
    }

    pub fn column_names(self) -> Vec<&'static str> {
        match self {
            TableType::Decomposition => vec![
                DECOMPOSITION_X_COLUMN,
                DECOMPOSITION_Y_COLUMN,
                DECOMPOSITION_Z_COLUMN,
                DECOMPOSITION_RESULT_COLUMN,
            ],
            TableType::BitwiseMajority => vec![
                BITWISE_X_COLUMN,
                BITWISE_Y_COLUMN,
                BITWISE_Z_COLUMN,
                BITWISE_MAJORITY_COLUMN,
            ],
            TableType::BitwiseChoose => vec![
                BITWISE_X_COLUMN,
                BITWISE_Y_COLUMN,
                BITWISE_Z_COLUMN,
                BITWISE_CHOOSE_COLUMN,
            ],
            TableType::Rotation0 => vec![
                ROTATION_INPUT_COLUMN,
                ROTATION_0_COLUMN,
            ],
            TableType::Rotation1 => vec![
                ROTATION_INPUT_COLUMN,
                ROTATION_1_COLUMN,
            ],
        }
    }
}

pub fn configure_decomposition_table<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    configure_table(meta, config, "decomposition", TableType::Decomposition);
}

pub fn configure_majority_table<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    configure_table(meta, config, "majority", TableType::BitwiseMajority);
}

pub fn configure_choose_table<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    configure_table(meta, config, "choose", TableType::BitwiseChoose);
}

pub fn configure_rot0_table<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    configure_table(meta, config, "rotation0", TableType::Rotation0);
}

pub fn configure_rot1_table<F: Field>(meta: &mut ConstraintSystem<F>, config: &ShaConfig) {
    configure_table(meta, config, "rotation1", TableType::Rotation1);
}

fn configure_table<F: Field>(
    meta: &mut ConstraintSystem<F>,
    config: &ShaConfig,
    table_name: &'static str,
    table_type: TableType,
) {
    meta.lookup_static(table_name, |meta| {
        let selector = meta.query_selector(table_type.selector(config));

        table_type
            .column_names()
            .into_iter()
            .zip(config.advices)
            .map(|(col_name, advice)| {
                (
                    selector.clone() * meta.query_advice(advice, Rotation::cur()),
                    StaticTableId(col_name.into()),
                )
            })
            .collect()
    });
}
