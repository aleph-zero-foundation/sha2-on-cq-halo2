use ff::Field;
use halo2curves::{
    batch_pairing::PairingBatcher,
    pairing::{Engine, MultiMillerLoop},
    serde::SerdeObject,
};

use crate::{
    plonk::{ProvingKey, VerifyingKey},
    transcript::{EncodedChallenge, TranscriptRead, TranscriptWrite},
};
use std::fmt::Debug;

use crate::plonk::Error;
use group::prime::PrimeCurveAffine;

use super::StaticTableId;

#[derive(Debug)]
pub struct Committed<E: MultiMillerLoop> {
    table_id: StaticTableId<String>,
    lhs: E::G1Affine,
}

impl<F: Field> super::Argument<F> {
    pub fn read_commitments<E, EC, T>(&self, transcript: &mut T) -> Result<Committed<E>, Error>
    where
        E: MultiMillerLoop + Debug,
        E::G1Affine: SerdeObject,
        E::G2Affine: SerdeObject,
        EC: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, EC>,
    {
        let lhs = transcript.read_point()?;
        Ok(Committed {
            lhs,
            table_id: self.table_id.clone(),
        })
    }
}

impl<E: MultiMillerLoop> Committed<E> {
    pub fn register_pairing(
        &self,
        vk: &VerifyingKey<E>,
        pairing_batcher: &mut PairingBatcher<E>,
    ) -> Result<(), Error>
    where
        E: MultiMillerLoop + Debug,
        E::G1Affine: SerdeObject,
        E::G2Affine: SerdeObject,
    {
        // TODO: make nicer error
        let committed_table = vk
            .static_table_mapping
            .get(&self.table_id)
            .expect("Key not exists");

        let rhs = committed_table.x;

        pairing_batcher.add_pairing(&[(self.lhs, rhs)]);

        Ok(())
    }
}
