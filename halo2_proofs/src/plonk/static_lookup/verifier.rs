use std::iter;

use super::super::{
    circuit::Expression, ChallengeBeta, ChallengeGamma, ChallengeTheta, ChallengeX,
};
use super::{Argument, StaticTableId};
use crate::poly::kzg::commitment::ParamsKZG;
use crate::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::{Error, VerifyingKey},
    poly::{commitment::MSM, Rotation, VerifierQuery},
    transcript::{EncodedChallenge, TranscriptRead},
};
use ff::Field;
use group::{prime::PrimeCurveAffine, Group};
use halo2curves::batch_pairing::PairingBatcher;
use halo2curves::pairing::{Engine, MultiMillerLoop};
use halo2curves::serde::SerdeObject;
use std::fmt::Debug;

pub struct CommittedWitness<E: MultiMillerLoop> {
    f: E::G1Affine,
    m: E::G1Affine,
    table_id: StaticTableId<String>,
}

pub struct CommittedLogDerivative<E: MultiMillerLoop> {
    committed_witness: CommittedWitness<E>,
    a: E::G1Affine,
    qa: E::G1Affine,
    a0: E::G1Affine,
    b0: E::G1Affine,
    p: E::G1Affine,
}

pub struct Evaluated<E: MultiMillerLoop> {
    committed: CommittedLogDerivative<E>,
    b0_eval: E::Scalar,
    f_eval: E::Scalar,
    a_at_zero: E::Scalar,
}

impl<F: FieldExt> Argument<F> {
    pub(in crate::plonk) fn read_committed<
        E: MultiMillerLoop + Debug,
        EC: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, EC>,
    >(
        &self,
        transcript: &mut T,
    ) -> Result<CommittedWitness<E>, Error> {
        let f = transcript.read_point()?;
        let m = transcript.read_point()?;

        Ok(CommittedWitness {
            f,
            m,
            table_id: self.table_id.clone(),
        })
    }
}

impl<E: MultiMillerLoop> CommittedWitness<E> {
    pub(in crate::plonk) fn read_committed_log_derivative<
        EC: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, EC>,
    >(
        self,
        transcript: &mut T,
    ) -> Result<CommittedLogDerivative<E>, Error> {
        let a = transcript.read_point()?;
        let qa = transcript.read_point()?;
        let a0 = transcript.read_point()?;
        let b0 = transcript.read_point()?;
        let p = transcript.read_point()?;

        Ok(CommittedLogDerivative {
            committed_witness: self,
            a,
            qa,
            a0,
            b0,
            p,
        })
    }
}

impl<E: MultiMillerLoop> CommittedLogDerivative<E> {
    pub(crate) fn evaluate<
        EC: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, EC>,
    >(
        self,
        transcript: &mut T,
    ) -> Result<Evaluated<E>, Error> {
        let b0_eval = transcript.read_scalar()?;
        let f_eval = transcript.read_scalar()?;
        let a_at_zero = transcript.read_scalar()?;

        Ok(Evaluated {
            committed: self,
            b0_eval,
            f_eval,
            a_at_zero,
        })
    }
}

impl<E> Evaluated<E>
where
    E: MultiMillerLoop + Debug,
    E::G1Affine: SerdeObject,
    E::G2Affine: SerdeObject,
{
    pub(in crate::plonk) fn register_pairings<'a>(
        &self,
        vk: &'a VerifyingKey<E>,
        params: &ParamsKZG<E>,
        pairing_batcher: &mut PairingBatcher<E>,
        beta: ChallengeBeta<E::G1Affine>,
    ) -> Result<(), Error> {
        let table = vk
            .static_table_mapping
            .get(&self.committed.committed_witness.table_id)
            .expect("Key does not exists");

        // Check that A encodes the correct values:
        // e(a, [T(x)]_2) = e(q_a, [Z_V(x)]_2) * e(m - ß * a, [1]_2)
        //
        // Check that B_0 has the appropriate degree:
        // e(b_0, [x_b0_bound]_2) = e(p, [1]_2)

        // e(m - ß * a, [1]_2)
        let m_minus_beta_a: E::G1Affine =
            (self.committed.committed_witness.m - (self.committed.a * *beta).into()).into();

        let a_at_zero_cm: E::G1Affine =
            (<E as Engine>::G1Affine::generator() * self.a_at_zero).into();

        pairing_batcher.add_pairing(&[
            // e(a, [T(x)]_2)
            (self.committed.a, table.t),
            // e(-q_a, [Z_V(x)]_2)
            ((-self.committed.qa).into(), table.zv),
            // e(- (m - ß * a), [1]_2)
            ((-m_minus_beta_a).into(), params.g2()),
            // e(b_0, [x_b0_bound]_2)
            (self.committed.b0, table.x_b0_bound),
            // e(-p, [1]_2)
            ((-self.committed.p).into(), params.g2()),
            // e(a - [a0], [1]_2)
            ((self.committed.a - a_at_zero_cm).into(), params.g2()),
            // e(-a0, [x]_2)
            ((-self.committed.a0).into(), params.s_g2()),
        ]);

        Ok(())
    }

    pub(in crate::plonk) fn expressions<'a>(
        &'a self,
        l_0: E::Scalar,
        l_last: E::Scalar,
        l_blind: E::Scalar,
        argument: &'a Argument<E::Scalar>,
        theta: ChallengeTheta<E::G1Affine>,
        beta: ChallengeBeta<E::G1Affine>,
        gamma: ChallengeGamma<E::G1Affine>,
        advice_evals: &[E::Scalar],
        fixed_evals: &[E::Scalar],
        instance_evals: &[E::Scalar],
        challenges: &[E::Scalar],
    ) -> impl Iterator<Item = E::Scalar> + 'a {
        // add all the custom pairings

        // let active_rows = E::Scalar::one() - (l_last + l_blind);

        // let product_expression = || {
        //     let compress_expressions = |expressions: &[Expression<E::Scalar>]| {
        //         expressions
        //             .iter()
        //             .map(|expression| {
        //                 expression.evaluate(
        //                     &|scalar| scalar,
        //                     &|_| panic!("virtual selectors are removed during optimization"),
        //                     &|query| fixed_evals[query.index],
        //                     &|query| advice_evals[query.index],
        //                     &|query| instance_evals[query.index],
        //                     &|challenge| challenges[challenge.index()],
        //                     &|a| -a,
        //                     &|a, b| a + &b,
        //                     &|a, b| a * &b,
        //                     &|a, scalar| a * &scalar,
        //                 )
        //             })
        //             .fold(E::Scalar::zero(), |acc, eval| acc * &*theta + &eval)
        //     };
        //     let right = self.product_eval
        //         * &(compress_expressions(&argument.input_expressions) + &*beta)
        //         * &(compress_expressions(&argument.table_expressions) + &*gamma);

        //     (left - &right) * &active_rows
        // };

        // std::iter::empty()
        //     .chain(
        //         // l_0(X) * (1 - z'(X)) = 0
        //         Some(l_0 * &(E::Scalar::one() - &self.product_eval)),
        //     )
        //     .chain(
        //         // l_last(X) * (z(X)^2 - z(X)) = 0
        //         Some(l_last * &(self.product_eval.square() - &self.product_eval)),
        //     )
        //     .chain(
        //         // (1 - (l_last(X) + l_blind(X))) * (
        //         //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        //         //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        //         // ) = 0
        //         Some(product_expression()),
        //     )
        //     .chain(Some(
        //         // l_0(X) * (a'(X) - s'(X)) = 0
        //         l_0 * &(self.permuted_input_eval - &self.permuted_table_eval),
        //     ))
        //     .chain(Some(
        //         // (1 - (l_last(X) + l_blind(X))) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
        //         (self.permuted_input_eval - &self.permuted_table_eval)
        //             * &(self.permuted_input_eval - &self.permuted_input_inv_eval)
        //             * &active_rows,
        //     ))
        iter::empty()
    }

    pub(in crate::plonk) fn queries<'r, M: MSM<E::G1Affine> + 'r>(
        &'r self,
        vk: &'r VerifyingKey<E>,
        x: ChallengeX<E::G1Affine>,
    ) -> impl Iterator<Item = VerifierQuery<'r, E::G1Affine, M>> + Clone {
        iter::empty()
            .chain(Some(VerifierQuery::new_commitment(
                &self.committed.b0,
                *x,
                self.b0_eval,
            )))
            .chain(Some(VerifierQuery::new_commitment(
                &self.committed.committed_witness.f,
                *x,
                self.f_eval,
            )))
    }
}
