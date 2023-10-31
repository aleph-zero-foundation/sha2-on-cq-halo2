mod bitwise;
mod initial_assignment;
mod limb_composition;
mod limb_decomposition;

pub use bitwise::*;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Value},
    plonk::Assigned,
};
pub use initial_assignment::*;
pub use limb_composition::*;
pub use limb_decomposition::*;
pub use r#final::*;
mod r#final;
mod rotation;
mod tables;
pub use tables::*;

pub use rotation::*;
pub struct CelledValue<'assign, F: Field> {
    pub cell: AssignedCell<&'assign Assigned<F>, F>,
    pub value: Value<F>,
}

pub struct LimbDecomposition<'assign, F: Field> {
    pub x: CelledValue<'assign, F>,
    pub y: CelledValue<'assign, F>,
    pub z: CelledValue<'assign, F>,
}
