use std::marker::PhantomData;

use ff::Field;
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::Bn256;
use rand_core::OsRng;

struct MyCircuit<F: Field>(PhantomData<F>);

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = ();

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        MyCircuit(PhantomData)
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        ()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        Ok(())
    }
}

#[test]
fn my_test_e2e() {
    const K: u32 = 3;
    let params = ParamsKZG::<Bn256>::new(K);
    let rng = OsRng;

    // Initialize the proving key
    let vk = keygen_vk(&params, &MyCircuit(PhantomData)).expect("keygen_vk should not fail");

    let pk = keygen_pk(&params, vk, &MyCircuit(PhantomData)).expect("keygen_pk should not fail");

    // Create proof
    let proof = {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        create_proof::<Bn256, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[MyCircuit(PhantomData)],
            &[&[&[]]],
            OsRng,
            &mut transcript,
        );

        transcript.finalize()
    };

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let verifier_params = params.verifier_params();
    let strategy = VerificationStrategy::<Bn256, VerifierGWC<_>>::new(verifier_params);

    verify_proof::<
        Bn256,
        VerifierGWC<_>,
        _,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<_>,
    >(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[&[&[]]],
        &mut transcript,
    );
}
