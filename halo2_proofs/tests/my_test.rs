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
}

impl<E: MultiMillerLoop<Scalar = F>, F: Field + FieldExt> Circuit<E> for MyCircuit<E> {
    type Config = Column<Advice>;

    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        meta.lookup_static("lookup_bits", |meta| {
            (
                meta.query_advice(advice, Rotation::cur()),
                StaticTableId(String::from("bits_table")),
            )
        });

        advice
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F, E = E>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        layouter.register_static_table(
            StaticTableId(String::from("bits_table")),
            self.table.clone(),
        );
        layouter.assign_region(
            || "",
            |mut region| {
                region.assign_advice(
                    config,
                    0,
                    Value::known(<E as Engine>::Scalar::from_u128(30)),
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

fn generate_table(params: &TableSRS<Bn256>, k: usize) -> StaticTable<Bn256> {
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

    let n = 1 << k;
    let table = StaticTableValues::new(&table_values, &params.g1());
    let committed = table.commit(params.g1().len(), params.g2(), n);

    StaticTable {
        opened: Some(table),
        committed: Some(committed),
    }
}

#[test]
fn my_test_e2e() {
    const K: u32 = 3;
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
    let s = <Bn256 as Engine>::Scalar::random(&mut rng);

    let table_1_size = 16;

    let table_1_srs = TableSRS::<Bn256>::setup_from_toxic_waste(table_1_size - 1, table_1_size, s);
    let table = generate_table(&table_1_srs, K as usize);
    let circuit = MyCircuit { table };

    let prover = MockProver::run(K, &circuit, vec![]).unwrap();
    prover.assert_satisfied();

    let params = ParamsKZG::<Bn256>::setup_from_toxic_waste(K, s);

    let config = StaticTableConfig::new(
        table_1_size,
        table_1_srs.g1_lagrange().to_vec(),
        table_1_srs.g_lagrange_opening_at_0().to_vec(),
    );
    let mut configs = BTreeMap::new();
    configs.insert(table_1_size, config);

    let b0_g1_bound = table_1_srs.g1()[((1 << K) + 1)..].to_vec();

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
