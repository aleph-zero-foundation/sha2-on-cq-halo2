mod bitwise_majority;
mod initial_assignment;
mod limb_decomposition;

pub use bitwise_majority::*;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Value};
use halo2_proofs::plonk::Assigned;
pub use initial_assignment::*;
pub use limb_decomposition::*;

pub struct LimbDecomposition<'assign, F: Field> {
    pub x_cell: AssignedCell<&'assign Assigned<F>, F>,
    pub y_cell: AssignedCell<&'assign Assigned<F>, F>,
    pub z_cell: AssignedCell<&'assign Assigned<F>, F>,

    pub x_value: Value<F>,
    pub y_value: Value<F>,
    pub z_value: Value<F>,
}
