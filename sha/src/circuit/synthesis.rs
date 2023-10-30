mod bitwise_choose;
mod bitwise_majority;
mod initial_assignment;
mod limb_composition;
mod limb_decomposition;

pub use bitwise_choose::*;
pub use bitwise_majority::*;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Cell, Value};
use halo2_proofs::plonk::Assigned;
pub use initial_assignment::*;
pub use limb_composition::*;
pub use limb_decomposition::*;
mod rotation;
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

pub struct BitwiseInput<'assign, 'limb, F: Field> {
    pub row_offset: usize,
    pub limbs1: &'limb LimbDecomposition<'assign, F>,
    pub limbs2: &'limb LimbDecomposition<'assign, F>,
    pub limbs3: &'limb LimbDecomposition<'assign, F>,
}

pub type BitwiseOutput<'assign, F> = LimbDecomposition<'assign, F>;

impl<'assign, 'limb, F: Field> BitwiseInput<'assign, 'limb, F> {
    pub fn x_values(&self) -> [Value<F>; 3] {
        [
            self.limbs1.x.value,
            self.limbs2.x.value,
            self.limbs3.x.value,
        ]
    }

    pub fn x_cells(&self) -> [&'limb Cell; 3] {
        [
            self.limbs1.x.cell.cell(),
            self.limbs2.x.cell.cell(),
            self.limbs3.x.cell.cell(),
        ]
    }

    pub fn y_values(&self) -> [Value<F>; 3] {
        [
            self.limbs1.y.value,
            self.limbs2.y.value,
            self.limbs3.y.value,
        ]
    }

    pub fn y_cells(&self) -> [&'limb Cell; 3] {
        [
            self.limbs1.y.cell.cell(),
            self.limbs2.y.cell.cell(),
            self.limbs3.y.cell.cell(),
        ]
    }

    pub fn z_values(&self) -> [Value<F>; 3] {
        [
            self.limbs1.z.value,
            self.limbs2.z.value,
            self.limbs3.z.value,
        ]
    }

    pub fn z_cells(&self) -> [&'limb Cell; 3] {
        [
            self.limbs1.z.cell.cell(),
            self.limbs2.z.cell.cell(),
            self.limbs3.z.cell.cell(),
        ]
    }
}
