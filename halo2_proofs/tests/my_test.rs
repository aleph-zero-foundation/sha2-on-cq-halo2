use group::{Curve, Group};
use rand::{Rng, SeedableRng};
use std::{collections::BTreeMap, fmt::Debug, marker::PhantomData};

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk,
        static_lookup::{
            StaticCommittedTable, StaticTable, StaticTableConfig, StaticTableId, StaticTableValues,
        },
        verify_proof, Advice, Circuit, Column, Selector,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, TableSRS},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::{
    bn256::{Bn256, Fq2Bytes},
    pairing::{Engine, MillerLoopResult, MultiMillerLoop},
    serde::SerdeObject,
    CurveAffine, FieldExt,
};
use rand_core::{OsRng, RngCore};

#[derive(Clone)]
struct MyCircuit<E: MultiMillerLoop> {
    table: StaticTable<E>,
    table_2: StaticTable<E>,
}

impl<E: MultiMillerLoop<Scalar = F>, F: Field + FieldExt> Circuit<E> for MyCircuit<E> {
    type Config = (Column<Advice>, Column<Advice>);

    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        let advice_2 = meta.advice_column();
        meta.lookup_static("lookup_bits", |meta| {
            vec![
                (
                    meta.query_advice(advice, Rotation::cur()),
                    StaticTableId(String::from("table")),
                ),
                (
                    meta.query_advice(advice_2, Rotation::cur()),
                    StaticTableId(String::from("table_2")),
                ),
            ]
        });

        (advice, advice_2)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F, E = E>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        layouter.register_static_table(StaticTableId(String::from("table")), self.table.clone());
        layouter
            .register_static_table(StaticTableId(String::from("table_2")), self.table_2.clone());

        layouter.assign_region(
            || "",
            |mut region| {
                region.assign_advice(
                    config.0,
                    0,
                    Value::known(<E as Engine>::Scalar::from_u128(30)),
                )?;
                region.assign_advice(
                    config.0,
                    1,
                    Value::known(<E as Engine>::Scalar::from_u128(6)),
                )?;
                region.assign_advice(
                    config.1,
                    0,
                    Value::known(<E as Engine>::Scalar::from_u128(15)),
                )?;
                region.assign_advice(
                    config.1,
                    1,
                    Value::known(<E as Engine>::Scalar::from_u128(3)),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

// ascii of cq
static SEED: [u8; 32] = [
    99, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

fn generate_table(params: &TableSRS<Bn256>, k: usize) -> (StaticTable<Bn256>, StaticTable<Bn256>) {
    use halo2curves::bn256::Fr;

    let table_values = [
        Fr::from(0),
        Fr::from(1),
        Fr::from(6),
        Fr::from(8),
        Fr::from(10),
        Fr::from(12),
        Fr::from(14),
        Fr::from(16),
        Fr::from(18),
        Fr::from(20),
        Fr::from(22),
        Fr::from(24),
        Fr::from(26),
        Fr::from(28),
        Fr::from(30),
        Fr::from(32),
    ];

    let table_2_values = [
        Fr::from(0),
        Fr::from(2),
        Fr::from(3),
        Fr::from(4),
        Fr::from(5),
        Fr::from(6),
        Fr::from(7),
        Fr::from(8),
        Fr::from(9),
        Fr::from(10),
        Fr::from(11),
        Fr::from(12),
        Fr::from(13),
        Fr::from(14),
        Fr::from(15),
        Fr::from(16),
    ];

    let n = 1 << k;
    let table = StaticTableValues::new(&table_values, &params.g1());
    let table_2 = StaticTableValues::new(&table_2_values, &params.g1());

    let committed = table.commit(params.g1().len(), params.g2(), n);
    let committed_2 = table_2.commit(params.g1().len(), params.g2(), n);

    let t1 = StaticTable {
        opened: Some(table),
        committed: Some(committed),
    };

    let t2 = StaticTable {
        opened: Some(table_2),
        committed: Some(committed_2),
    };

    (t1, t2)
}

#[test]
fn my_test_e2e() {
    const K: u32 = 3;
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
    let s = <Bn256 as Engine>::Scalar::random(&mut rng);

    let table_16_size = 16;

    let table_16_srs =
        TableSRS::<Bn256>::setup_from_toxic_waste(table_16_size - 1, table_16_size, s);
    let (table, table_2) = generate_table(&table_16_srs, K as usize);
    let circuit = MyCircuit { table, table_2 };

    let prover = MockProver::run(K, &circuit, vec![]).unwrap();
    prover.assert_satisfied();

    let params = ParamsKZG::<Bn256>::setup_from_toxic_waste(K, s);

    let config = StaticTableConfig::new(
        table_16_size,
        table_16_srs.g1_lagrange().to_vec(),
        table_16_srs.g_lagrange_opening_at_0().to_vec(),
    );
    let mut configs = BTreeMap::new();
    configs.insert(table_16_size, config);

    let b0_g1_bound = table_16_srs.g1()[((1 << K) + 1)..].to_vec();

    // Initialize keys
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk =
        keygen_pk(&params, configs, b0_g1_bound, vk, &circuit).expect("keygen_pk should not fail");

    // Create proof
    let proof = {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        create_proof::<Bn256, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[]],
            OsRng,
            &mut transcript,
        )
        .unwrap();

        transcript.finalize()
    };

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let verifier_params = params.verifier_params();
    let strategy = VerificationStrategy::<Bn256, VerifierGWC<_>>::new(verifier_params);

    let p_batcher = verify_proof::<
        Bn256,
        VerifierGWC<_>,
        _,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<_>,
    >(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[&[]],
        &mut transcript,
    )
    .unwrap();

    let batched_tuples = p_batcher.finalize();
    let result = Bn256::multi_miller_loop(
        &batched_tuples
            .iter()
            .map(|(g1, g2)| (g1, g2))
            .collect::<Vec<_>>(),
    );

    let pairing_result = result.final_exponentiation();
    assert!(bool::from(pairing_result.is_identity()));
}
