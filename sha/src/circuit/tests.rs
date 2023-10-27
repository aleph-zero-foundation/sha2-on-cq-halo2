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
use crate::circuit::tables::DecompositionTables;

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
        decomposition: DecompositionTables {
            decomp_x: StaticTable { opened: Some(table_x), committed: Some(committed_x) },
            decomp_y: StaticTable { opened: Some(table_y), committed: Some(committed_y) },
            decomp_z: StaticTable { opened: Some(table_z), committed: Some(committed_z) },
            decomp: StaticTable { opened: Some(table_maj), committed: Some(committed_maj) },
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
    println!("Generated SRS");

    let tables = generate_tables::<TestLimb>(&table_srs, k);
    println!("Generated tables");

    let circuit = ShaCircuit::<Bn256, TestLimb>::new(0, 1, 2, 3, 4, 5, 6, 7, tables);

    MockProver::run(k, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
}
