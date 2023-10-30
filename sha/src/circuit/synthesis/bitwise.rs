use crate::circuit::config::ShaConfig;
use crate::circuit::synthesis::bitwise::BitwiseOperation::Choose;
use crate::circuit::synthesis::bitwise::LimbPart::{X, Y, Z};
use crate::circuit::synthesis::{CelledValue, LimbDecomposition};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Cell, Layouter, Value};
use halo2_proofs::halo2curves::pairing::{Engine, MultiMillerLoop};
use halo2_proofs::plonk::{Error, Selector};
use BitwiseOperation::Majority;

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

#[derive(Clone, Copy)]
enum BitwiseOperation {
    Majority,
    Choose,
}

impl BitwiseOperation {
    pub fn selector(&self, config: &ShaConfig) -> Selector {
        match self {
            Majority => config.majority_selector(),
            Choose => config.choose_selector(),
        }
    }

    pub fn compute<F: Field>(&self, inputs: [Value<F>; 3]) -> Value<F> {
        Value::known(Default::default()) // todo
    }
}

#[derive(Clone, Copy)]
enum LimbPart {
    X,
    Y,
    Z,
}

impl LimbPart {
    pub fn values<F: Field>(&self, input: &BitwiseInput<F>) -> [Value<F>; 3] {
        match self {
            X => input.x_values(),
            Y => input.y_values(),
            Z => input.z_values(),
        }
    }

    pub fn cells<'limb, F: Field>(&self, input: &BitwiseInput<'_, 'limb, F>) -> [&'limb Cell; 3] {
        match self {
            X => input.x_cells(),
            Y => input.y_cells(),
            Z => input.z_cells(),
        }
    }

    pub fn offset(&self) -> usize {
        match self {
            X => 0,
            Y => 1,
            Z => 2,
        }
    }
}

fn region_name(op: BitwiseOperation, limb_part: LimbPart) -> &'static str {
    match (op, limb_part) {
        (Majority, X) => "majority: x",
        (Majority, Y) => "majority: y",
        (Majority, Z) => "majority: z",
        (Choose, X) => "choose: x",
        (Choose, Y) => "choose: y",
        (Choose, Z) => "choose: z",
    }
}

pub fn bitwise_majority<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: BitwiseInput<'assign, 'limb, E::Scalar>,
) -> Result<BitwiseOutput<'assign, E::Scalar>, Error> {
    bitwise_op(layouter, config, input, Majority)
}

pub fn bitwise_choose<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: BitwiseInput<'assign, 'limb, E::Scalar>,
) -> Result<BitwiseOutput<'assign, E::Scalar>, Error> {
    bitwise_op(layouter, config, input, Choose)
}

fn bitwise_op<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    input: BitwiseInput<'assign, 'limb, E::Scalar>,
    bitwise_operation: BitwiseOperation,
) -> Result<BitwiseOutput<'assign, E::Scalar>, Error> {
    let x = bitwise_row(layouter, config, bitwise_operation, X, &input)?;
    let y = bitwise_row(layouter, config, bitwise_operation, Y, &input)?;
    let z = bitwise_row(layouter, config, bitwise_operation, Z, &input)?;

    Ok(LimbDecomposition { x, y, z })
}

fn bitwise_row<'assign, 'limb, E: MultiMillerLoop>(
    layouter: &mut impl Layouter<E::Scalar, E = E>,
    config: &ShaConfig,
    bitwise_operation: BitwiseOperation,
    limb_part: LimbPart,
    input: &BitwiseInput<'assign, 'limb, E::Scalar>,
) -> Result<CelledValue<'assign, E::Scalar>, Error> {
    layouter.assign_region(
        || region_name(bitwise_operation, limb_part),
        |mut region| {
            let offset = input.row_offset + limb_part.offset();

            bitwise_operation
                .selector(&config)
                .enable(&mut region, offset)?;

            let values = limb_part.values(input);
            let cells = limb_part.cells(input);

            let w0 = region.assign_advice(config.advices[0], offset, values[0])?;
            let w1 = region.assign_advice(config.advices[1], offset, values[1])?;
            let w2 = region.assign_advice(config.advices[2], offset, values[2])?;

            region.constrain_equal(w0.cell(), cells[0]);
            region.constrain_equal(w1.cell(), cells[1]);
            region.constrain_equal(w2.cell(), cells[2]);

            let value = bitwise_operation.compute(values);
            let w_ch = region.assign_advice(config.advices[3], offset, value)?;

            Ok(CelledValue { cell: w_ch, value })
        },
    )
}
