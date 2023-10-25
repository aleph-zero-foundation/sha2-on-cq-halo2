use crate::tables::Limbs;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::static_lookup::{StaticTable, StaticTableId};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

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

pub struct ShaCircuit<E: MultiMillerLoop, L> {
    a: Value<E::Scalar>,
    b: Value<E::Scalar>,
    c: Value<E::Scalar>,
    d: Value<E::Scalar>,
    e: Value<E::Scalar>,
    f: Value<E::Scalar>,
    g: Value<E::Scalar>,
    h: Value<E::Scalar>,

    tables: ShaTables<E>,

    _marker: PhantomData<(E, L)>,
}

impl<E: MultiMillerLoop, L> ShaCircuit<E, L> {
    pub fn new(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
        tables: ShaTables<E>,
    ) -> Self {
        Self {
            a: Value::known(E::Scalar::from(a as u64)),
            b: Value::known(E::Scalar::from(b as u64)),
            c: Value::known(E::Scalar::from(c as u64)),
            d: Value::known(E::Scalar::from(d as u64)),
            e: Value::known(E::Scalar::from(e as u64)),
            f: Value::known(E::Scalar::from(f as u64)),
            g: Value::known(E::Scalar::from(g as u64)),
            h: Value::known(E::Scalar::from(h as u64)),

            tables,

            _marker: PhantomData::default(),
        }
    }
}

impl<E: MultiMillerLoop, L> Default for ShaCircuit<E, L> {
    fn default() -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            c: Value::unknown(),
            d: Value::unknown(),
            e: Value::unknown(),
            f: Value::unknown(),
            g: Value::unknown(),
            h: Value::unknown(),
            tables: ShaTables::default(),
            _marker: PhantomData::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShaConfig {
    advices: [Column<Advice>; 4],
    instance: Column<Instance>,
    selectors: [Selector; 4],
    fixed: [Column<Fixed>; 2],
}

impl<E: MultiMillerLoop, L: Limbs> Circuit<E> for ShaCircuit<E, L> {
    type Config = ShaConfig;
    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
        // ================
        // COLUMNS CREATION
        // ================
        let advices = (0..4)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<_>>();
        let instance = meta.instance_column();
        let selectors = (0..4).map(|_| meta.selector()).collect::<Vec<_>>();
        let fixed = (0..2).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        // ===============
        // TABLES CREATION
        // ===============
        meta.lookup_static("majority", |meta| {
            vec![
                (
                    meta.query_advice(advices[0], Rotation::cur()),
                    StaticTableId("x".into()),
                ),
                (
                    meta.query_advice(advices[1], Rotation::cur()),
                    StaticTableId("y".into()),
                ),
                (
                    meta.query_advice(advices[2], Rotation::cur()),
                    StaticTableId("z".into()),
                ),
                (
                    meta.query_advice(advices[3], Rotation::cur()),
                    StaticTableId("maj".into()),
                ),
            ]
        });

        // =============
        // GATE CREATION
        // =============
        meta.create_gate("simple decomposition", |meta| {
            let word = meta.query_advice(advices[0], Rotation::cur());
            let x = meta.query_advice(advices[1], Rotation::cur());
            let y = meta.query_advice(advices[2], Rotation::cur());
            let z = meta.query_advice(advices[3], Rotation::cur());

            let x_shift = meta.query_fixed(fixed[0], Rotation::cur());
            let y_shift = meta.query_fixed(fixed[1], Rotation::cur());

            let s = meta.query_selector(selectors[0]);

            vec![s * (word - (x * x_shift + y * y_shift + z))]
        });

        ShaConfig {
            advices: advices.try_into().unwrap(),
            instance,
            selectors: selectors.try_into().unwrap(),
            fixed: fixed.try_into().unwrap(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<E::Scalar, E = E>,
    ) -> Result<(), Error> {
        // ==========================================================================
        // Assign inputs (a..h) and copy 6 of them right away to the instance column.
        // ==========================================================================
        let input_cells = layouter.assign_region(
            || "assign inputs",
            |mut region| {
                let a = region.assign_advice(config.advices[0], 0, self.a)?;
                let b = region.assign_advice(config.advices[1], 0, self.b)?;
                let c = region.assign_advice(config.advices[2], 0, self.c)?;
                let d = region.assign_advice(config.advices[3], 0, self.d)?;

                let e = region.assign_advice(config.advices[0], 1, self.e)?;
                let f = region.assign_advice(config.advices[1], 1, self.f)?;
                let g = region.assign_advice(config.advices[2], 1, self.g)?;
                let h = region.assign_advice(config.advices[3], 1, self.h)?;

                Ok([a, b, c, d, e, f, g, h])
            },
        )?;

        layouter.constrain_instance(*input_cells[0].cell(), config.instance, 1); // b' = a
        layouter.constrain_instance(*input_cells[1].cell(), config.instance, 2); // c' = b
        layouter.constrain_instance(*input_cells[2].cell(), config.instance, 3); // d' = c

        layouter.constrain_instance(*input_cells[4].cell(), config.instance, 5); // f' = e
        layouter.constrain_instance(*input_cells[5].cell(), config.instance, 6); // g' = f
        layouter.constrain_instance(*input_cells[6].cell(), config.instance, 7); // h' = g

        // =========================================
        // Decompose a,b,c,e,f,g into shorter limbs.
        // =========================================
        let words = [self.a, self.b, self.c, self.e, self.f, self.g];
        let cells = [
            &input_cells[0],
            &input_cells[1],
            &input_cells[2],
            &input_cells[4],
            &input_cells[5],
            &input_cells[6],
        ];
        let names = ["a", "b", "c", "e", "f", "g"];

        let mut limb_cells = vec![];

        for (offset, ((word, input_cell), name)) in words.iter().zip(cells).zip(names).enumerate() {
            let new_cells = layouter.assign_region(
                || format!("{name}: limb decomposition"),
                |mut region| {
                    config.selectors[0].enable(&mut region, offset + 2)?;

                    let word_cell = region.assign_advice(config.advices[0], offset + 2, *word)?;
                    region.constrain_equal(word_cell.cell(), input_cell.cell());

                    let shift = L::SECOND_LIMB_LEN;
                    let x = word
                        .map(|w| w.get_lower_128() >> (shift + shift))
                        .map(E::Scalar::from_u128);
                    let y = word
                        .map(|w| (w.get_lower_128() >> shift) % (1 << shift))
                        .map(E::Scalar::from_u128);
                    let z = word
                        .map(|w| w.get_lower_128() % (1 << shift))
                        .map(E::Scalar::from_u128);

                    let x_cell = region.assign_advice(config.advices[1], offset + 2, x)?;
                    let y_cell = region.assign_advice(config.advices[2], offset + 2, y)?;
                    let z_cell = region.assign_advice(config.advices[3], offset + 2, z)?;

                    Ok((x_cell, y_cell, z_cell))
                },
            )?;
            limb_cells.push(new_cells);
        }

        // =========================
        // Compute bitwise majority.
        // =========================

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::{ShaCircuit, ShaTables};
    use crate::tables;
    use crate::tables::{decompose_table, Limbs, TinyLimbs};
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
    use halo2_proofs::halo2curves::pairing::Engine;
    use halo2_proofs::plonk::static_lookup::{StaticTable, StaticTableValues};
    use halo2_proofs::poly::kzg::commitment::TableSRS;
    use rand_core::SeedableRng;

    fn generate_tables<L: Limbs>(params: &TableSRS<Bn256>, k: u32) -> ShaTables<Bn256> {
        let n = 1 << k;

        let t_maj = tables::create_maj_table::<L>();
        let (t_x, t_y, t_z, t_maj) = decompose_table::<Fr>(t_maj);

        let table_x = StaticTableValues::new(&t_x, &params.g1());
        let table_y = StaticTableValues::new(&t_y, &params.g1());
        let table_z = StaticTableValues::new(&t_z, &params.g1());
        let table_maj = StaticTableValues::new(&t_maj, &params.g1());

        let committed_x = table_x.commit(params.g1().len(), params.g2(), n);
        let committed_y = table_y.commit(params.g1().len(), params.g2(), n);
        let committed_z = table_z.commit(params.g1().len(), params.g2(), n);
        let committed_maj = table_maj.commit(params.g1().len(), params.g2(), n);

        ShaTables {
            x: StaticTable {
                opened: Some(table_x),
                committed: Some(committed_x),
            },
            y: StaticTable {
                opened: Some(table_y),
                committed: Some(committed_y),
            },
            z: StaticTable {
                opened: Some(table_z),
                committed: Some(committed_z),
            },
            maj: StaticTable {
                opened: Some(table_maj),
                committed: Some(committed_maj),
            },
        }
    }

    #[test]
    fn test_positive_case() {
        type TestLimb = TinyLimbs;

        let k = 5u32;
        let table_len = 1 << TestLimb::full_word_len();

        let mut rng = rand_chacha::ChaCha8Rng::from_seed([41; 32]);
        let s = <Bn256 as Engine>::Scalar::random(&mut rng);

        let table_srs = TableSRS::<Bn256>::setup_from_toxic_waste(table_len - 1, table_len, s);
        println!("Generated SRS");

        let tables = generate_tables::<TestLimb>(&table_srs, k);
        println!("Generated tables");

        let circuit = ShaCircuit::<Bn256, TestLimb>::new(0, 1, 2, 3, 4, 5, 6, 7, tables);

        MockProver::run(k, &circuit, vec![])
            .unwrap()
            .assert_satisfied();
    }
}
