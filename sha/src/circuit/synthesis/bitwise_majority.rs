use crate::circuit::config::ShaConfig;
use crate::circuit::synthesis::{CelledValue, LimbDecomposition};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Cell, Layouter, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::{Assigned, Error};

pub struct BitwiseMajorityInput<'assign, 'limb, F: Field> {
    pub row_offset: usize,
    pub a_limbs: &'limb LimbDecomposition<'assign, F>,
    pub b_limbs: &'limb LimbDecomposition<'assign, F>,
    pub c_limbs: &'limb LimbDecomposition<'assign, F>,
}

pub type BitwiseMajorityOutput<'assign, F> = LimbDecomposition<'assign, F>;

pub fn bitwise_majority<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: BitwiseMajorityInput<'assign, 'limb, E::Scalar>,
) -> Result<BitwiseMajorityOutput<'assign, E::Scalar>, Error> {
    let x = bitwise_majority_row(
        layouter,
        config,
        input.row_offset,
        "bitwise majority: x",
        input.x_values(),
        input.x_cells(),
    )?;
    let y = bitwise_majority_row(
        layouter,
        config,
        input.row_offset + 1,
        "bitwise majority: y",
        input.y_values(),
        input.y_cells(),
    )?;
    let z = bitwise_majority_row(
        layouter,
        config,
        input.row_offset + 2,
        "bitwise majority: z",
        input.z_values(),
        input.z_cells(),
    )?;

    Ok(LimbDecomposition { x, y, z })
}

fn bitwise_majority_row<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    row_offset: usize,
    region_name: &str,
    values: [Value<E::Scalar>; 3],
    cells: [&'limb Cell; 3],
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || region_name,
        |mut region| {
            config.majority_selector().enable(&mut region, row_offset)?;

            let w0 = region.assign_advice(config.advices[0], row_offset, values[0])?;
            let w1 = region.assign_advice(config.advices[1], row_offset, values[1])?;
            let w2 = region.assign_advice(config.advices[2], row_offset, values[2])?;

            region.constrain_equal(w0.cell(), cells[0]);
            region.constrain_equal(w1.cell(), cells[1]);
            region.constrain_equal(w2.cell(), cells[2]);

            let value = Value::known(E::Scalar::default()); // todo compute true majority
            let w_maj = region.assign_advice(config.advices[3], row_offset, value)?;

            Ok(CelledValue { cell: w_maj, value })
        },
    )
}

impl<'assign, 'limb, F: Field> BitwiseMajorityInput<'assign, 'limb, F> {
    fn x_values(&self) -> [Value<F>; 3] {
        [
            self.a_limbs.x.value,
            self.b_limbs.x.value,
            self.c_limbs.x.value,
        ]
    }

    fn x_cells(&self) -> [&'limb Cell; 3] {
        [
            self.a_limbs.x.cell.cell(),
            self.b_limbs.x.cell.cell(),
            self.c_limbs.x.cell.cell(),
        ]
    }

    fn y_values(&self) -> [Value<F>; 3] {
        [
            self.a_limbs.y.value,
            self.b_limbs.y.value,
            self.c_limbs.y.value,
        ]
    }

    fn y_cells(&self) -> [&'limb Cell; 3] {
        [
            self.a_limbs.y.cell.cell(),
            self.b_limbs.y.cell.cell(),
            self.c_limbs.y.cell.cell(),
        ]
    }

    fn z_values(&self) -> [Value<F>; 3] {
        [
            self.a_limbs.z.value,
            self.b_limbs.z.value,
            self.c_limbs.z.value,
        ]
    }

    fn z_cells(&self) -> [&'limb Cell; 3] {
        [
            self.a_limbs.z.cell.cell(),
            self.b_limbs.z.cell.cell(),
            self.c_limbs.z.cell.cell(),
        ]
    }
}
