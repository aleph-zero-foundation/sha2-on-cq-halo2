mod bitwise_majority;
mod initial_assignment;
mod limb_composition;
mod limb_decomposition;

pub use bitwise_majority::*;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Value};
use halo2_proofs::plonk::Assigned;
pub use initial_assignment::*;
pub use limb_composition::*;
pub use limb_decomposition::*;

pub struct CelledValue<'assign, F: Field> {
    pub cell: AssignedCell<&'assign Assigned<F>, F>,
    pub value: Value<F>,
}

pub struct LimbDecomposition<'assign, F: Field> {
    pub x: CelledValue<'assign, F>,
    pub y: CelledValue<'assign, F>,
    pub z: CelledValue<'assign, F>,
}
