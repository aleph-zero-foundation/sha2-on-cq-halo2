use group::{Curve, Group};
use rand::{Rng, SeedableRng};
use std::{fmt::Debug, marker::PhantomData};

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk,
        static_lookup::{StaticCommittedTable, StaticTable, StaticTableId, StaticTableValues},
        verify_proof, Advice, Circuit, Column,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
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

impl<E: MultiMillerLoop<Scalar = F>, F: Field> Circuit<E> for MyCircuit<E> {
    type Config = Column<Advice>;

    type FloorPlanner = SimpleFloorPlanner<E>;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        meta.create_gate("", |meta| vec![meta.query_advice(advice, Rotation::cur())]);

        let selector = meta.selector();
        meta.create_gate("", |meta| vec![meta.query_selector(selector)]);
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
        // layouter.assign_region(
        //     || "",
        //     |mut region| { region.assign_advice(config, 0, Value::known(F::one())) },
        // )?;

        Ok(())
    }
}

// ascii of cq
static SEED: [u8; 32] = [
    99, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

fn generate_table(params: &ParamsKZG<Bn256>, k: usize) -> StaticTable<Bn256> {
    use halo2curves::bn256::Fr;

    let table_values = [
        Fr::from(1),
        Fr::from(4),
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

    let table = StaticTableValues::new(&table_values, &params.get_g());
    let n = 1 << k;
    let committed = table.commit(params.g1_srs().len(), params.g2_srs(), n);

    StaticTable {
        opened: Some(table),
        committed: Some(committed),
    }
}

#[test]
fn my_test_e2e() {
    const K: u32 = 2;
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);

    let table_size = 16u32;

    let params = ParamsKZG::<Bn256>::setup(table_size - 1, table_size, &mut rng);
    let table = generate_table(&params, K as usize);
    let circuit = MyCircuit { table };

    // Initialize keys
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

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
