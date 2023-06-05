use ff::Field;
use halo2curves::{
    pairing::{Engine, MultiMillerLoop},
    serde::SerdeObject,
};

use crate::{
    plonk::ProvingKey,
    transcript::{EncodedChallenge, TranscriptWrite},
};
use std::fmt::Debug;

use crate::plonk::Error;
use group::prime::PrimeCurveAffine;

#[derive(Debug)]
pub struct Committed<E: MultiMillerLoop> {
    lhs: E::G1Affine,
}

impl<F: Field> super::Argument<F> {
    pub fn commit<E, EC, T>(
        &self,
        pk: ProvingKey<E>,
        transcript: &mut T,
    ) -> Result<Committed<E>, Error>
    where
        E: MultiMillerLoop + Debug,
        E::G1Affine: SerdeObject,
        E::G2Affine: SerdeObject,
        EC: EncodedChallenge<E::G1Affine>,
        T: TranscriptWrite<E::G1Affine, EC>,
    {
        // TODO: make nicer error
        let table = pk
            .static_table_mapping
            .get(&self.table_id)
            .expect("Key not exists");
        let x_inv = table.x.invert().unwrap();

        let cm = Committed {
            lhs: (<E as Engine>::G1Affine::generator() * x_inv).into(),
        };

        transcript.write_point(cm.lhs)?;
        Ok(cm)
    }
}
