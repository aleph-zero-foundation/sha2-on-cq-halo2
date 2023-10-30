use halo2_proofs::{
    arithmetic::Field,
    dev::MockProver,
    halo2curves::{
        bn256::{Bn256, Fr},
        pairing::Engine,
    },
    plonk::static_lookup::{StaticTable, StaticTableValues},
    poly::kzg::commitment::TableSRS,
};
use rand_core::SeedableRng;

use crate::{
    circuit::{tables::DecompositionTables, ShaCircuit, ShaTables},
    tables,
    tables::{decompose_table, Limbs, TinyLimbs},
};

fn generate_tables<L: Limbs>(params: &TableSRS<Bn256>, k: u32) -> ShaTables<Bn256> {
    let n = 1 << k;

    let t_maj = tables::create_maj_table::<L>();
    let (t_x, t_y, t_z, t_maj) = decompose_table::<Fr>(t_maj);

    let table_x = StaticTableValues::new(&t_x, &params.g1());
    let table_y = StaticTableValues::new(&t_y, &params.g1());
    let table_z = StaticTableValues::new(&t_z, &params.g1());
    let table_maj = StaticTableValues::new(&t_maj, &params.g1());

    // let committed_x = table_x.commit(params.g1().len(), params.g2(), n);
    // let committed_y = table_y.commit(params.g1().len(), params.g2(), n);
    // let committed_z = table_z.commit(params.g1().len(), params.g2(), n);
    // let committed_maj = table_maj.commit(params.g1().len(), params.g2(), n);

    ShaTables {
        decomposition: DecompositionTables {
            decomp_x: StaticTable {
                opened: Some(table_x),
                committed: None,
            },
            decomp_y: StaticTable {
                opened: Some(table_y),
                committed: None,
            },
            decomp_z: StaticTable {
                opened: Some(table_z),
                committed: None,
            },
            decomp: StaticTable {
                opened: Some(table_maj),
                committed: None,
            },
        },
        ..Default::default()
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

    let tables = generate_tables::<TestLimb>(&table_srs, k);

    let circuit = ShaCircuit::<Bn256, TestLimb>::new(0, 1, 2, 3, 4, 5, 6, 7, tables);

    MockProver::run(
        k,
        &circuit,
        vec![vec![
            7.into(),
            0.into(),
            1.into(),
            2.into(),
            3.into(),
            4.into(),
            5.into(),
            6.into(),
        ]],
    )
    .unwrap()
    .assert_satisfied();
}
