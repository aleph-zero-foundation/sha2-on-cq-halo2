use ff::Field;
use halo2curves::{
    bn256::{G1Affine, G1},
    pairing::{Engine, MultiMillerLoop},
    serde::SerdeObject,
    FieldExt,
};

// TODO: COMPUTE A(0) COMMITMENT FROM LAGRANGE AT 0 COMMITMENTS

use crate::{
    arithmetic::{best_multiexp, eval_polynomial},
    plonk::{
        evaluation::evaluate, ChallengeBeta, ChallengeTheta, ChallengeX, Expression, ProvingKey,
    },
    poly::{
        commitment::{Blind, Params, ParamsProver},
        kzg::commitment::{ParamsCQ, ParamsKZG},
        Coeff, EvaluationDomain, LagrangeCoeff, Polynomial, ProverQuery,
    },
    transcript::{EncodedChallenge, TranscriptWrite},
};
use std::{collections::BTreeMap, fmt::Debug, iter};

use crate::plonk::Error;
use group::{prime::PrimeCurveAffine, Curve, Group};

use super::StaticTableId;

#[derive(Debug)]
pub struct Committed<E: MultiMillerLoop> {
    pub(in crate::plonk) f: Polynomial<E::Scalar, LagrangeCoeff>,
    pub(in crate::plonk) m_sparse: BTreeMap<usize, E::Scalar>,
    pub(in crate::plonk) table_id: StaticTableId<String>,
}

#[derive(Debug, Clone)]
pub struct CommittedLogDerivative<E: MultiMillerLoop> {
    pub(in crate::plonk) b0: Polynomial<E::Scalar, Coeff>,
    pub(in crate::plonk) f: Polynomial<E::Scalar, Coeff>,
    pub(in crate::plonk) a_at_zero: E::Scalar,
}

pub(in crate::plonk) struct Evaluated<E: MultiMillerLoop> {
    constructed: CommittedLogDerivative<E>,
}

impl<F: FieldExt> super::Argument<F> {
    pub(in crate::plonk) fn commit<'a, E, EC, T>(
        &self,
        pk: &ProvingKey<E>,
        params: &ParamsKZG<E>,
        domain: &EvaluationDomain<F>,
        theta: ChallengeTheta<E::G1Affine>,
        challenges: &'a [E::Scalar],
        advice_values: &'a [Polynomial<E::Scalar, LagrangeCoeff>],
        fixed_values: &'a [Polynomial<E::Scalar, LagrangeCoeff>],
        instance_values: &'a [Polynomial<E::Scalar, LagrangeCoeff>],
        transcript: &mut T,
    ) -> Result<Committed<E>, Error>
    where
        E: MultiMillerLoop<Scalar = F> + Debug,
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

        let compress_expressions = |expressions: &[Expression<E::Scalar>]| {
            let compressed_expression = expressions
                .iter()
                .map(|expression| {
                    pk.vk.domain.lagrange_from_vec(evaluate(
                        expression,
                        params.n() as usize,
                        1,
                        fixed_values,
                        advice_values,
                        instance_values,
                        challenges,
                    ))
                })
                .fold(domain.empty_lagrange(), |acc, expression| {
                    acc * *theta + &expression
                });
            compressed_expression
        };

        // Get values of input expressions involved in the lookup and compress them
        // for now we just have one expression here
        let f = compress_expressions(&[self.input.clone()]);

        // NOTE: For completeness we just ignore blinding rows
        // make sure to add selector and change cq as in our hackmd for soundness
        let blinding_factors = pk.vk.cs.blinding_factors();
        let usable_rows = params.n() as usize - (blinding_factors + 1);
        let mut m_sparse = BTreeMap::<usize, E::Scalar>::default();
        for fi in f.iter().take(usable_rows) {
            println!("fi: {:?}", fi);
            let index = table
                .value_index_mapping
                .get(fi)
                .expect(&format!("{:?} not in table", *fi));

            println!("index: {}", index);
            let multiplicity = m_sparse.entry(*index).or_insert(E::Scalar::zero());
            *multiplicity += E::Scalar::one();
            println!("multiplicity: {:?}", multiplicity);
        }

        // zk is not currently supported
        let blind = Blind(E::Scalar::zero());
        let f_cm: E::G1Affine = params.commit_lagrange(&f, blind).into();

        let mut m_cm = E::G1::identity();
        for (&index, &multiplicity) in m_sparse.iter() {
            m_cm = pk.params_cq.g1_lagrange[index] * multiplicity + m_cm;
        }

        let m_cm: E::G1Affine = m_cm.into();

        transcript.write_point(f_cm)?;
        transcript.write_point(m_cm)?;

        Ok(Committed {
            f,
            m_sparse,
            table_id: self.table_id.clone(),
        })
    }
}

impl<E: MultiMillerLoop> Committed<E> {
    pub(in crate::plonk) fn commit_log_derivatives<'a, EC, T>(
        &self,
        pk: &ProvingKey<E>,
        params: &ParamsKZG<E>,
        cq_params: &ParamsCQ<E>,
        domain: &EvaluationDomain<E::Scalar>,
        beta: ChallengeBeta<E::G1Affine>,
        transcript: &mut T,
    ) -> Result<CommittedLogDerivative<E>, Error>
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

        let mut a_cm = E::G1::identity();
        let mut qa_cm = E::G1::identity();
        let mut a0_cm = E::G1::identity();

        let table_values: Vec<E::Scalar> = table.value_index_mapping.keys().cloned().collect();
        // step 2&3&4: computes A sparse representation, a commitment and qa commitment in single pass
        for (&index, &multiplicity) in self.m_sparse.iter() {
            let a_i = multiplicity * (table_values[index] + *beta).invert().unwrap();

            // println!("index i: {}", index);
            // println!("mul i: {:?}", multiplicity);

            a_cm = pk.params_cq.g1_lagrange[index] * a_i + a_cm;
            qa_cm = table.qs[index] * a_i + qa_cm;
            a0_cm = pk.params_cq.g_lagrange_opening_at_0[index] * a_i + a0_cm;
        }

        let blinding_factors = pk.vk.cs.blinding_factors();
        let usable_rows = params.n() as usize - (blinding_factors + 1);
        let mut bs: Vec<_> = self
            .f
            .iter()
            .take(usable_rows)
            .map(|&fi| (fi + *beta).invert().unwrap())
            .collect();

        bs.extend_from_slice(&vec![E::Scalar::zero(); blinding_factors + 1]);

        EvaluationDomain::ifft(
            bs.as_mut_slice(),
            domain.get_omega_inv(),
            domain.k(),
            domain.ifft_divisor(),
        );

        // (b - b(0)) / X
        let mut b0_poly_coeffs = bs[1..].to_vec();

        // TODO: QB part will be handled with full quotient argument and multiopen

        let n = 1 << domain.k();
        let mut p_poly_coeffs: Vec<<E as Engine>::Scalar> =
            vec![E::Scalar::zero(); table.size - 1 - (n - 2)];
        p_poly_coeffs.extend_from_slice(&b0_poly_coeffs);
        assert_eq!(p_poly_coeffs.len(), table.size);

        // convert to correct poly types
        let b_poly = domain.coeff_from_vec(bs);
        // let p_poly = table_domain.coeff_from_vec(p_poly_coeffs);

        // TODO append 0 here to fix issue
        b0_poly_coeffs.push(E::Scalar::zero());
        let b0_poly = domain.coeff_from_vec(b0_poly_coeffs);

        // write all commitements to transcript
        transcript.write_point(a_cm.into())?;
        transcript.write_point(qa_cm.into())?;
        transcript.write_point(a0_cm.into())?;

        let b0_cm = params.commit(&b0_poly, Blind(E::Scalar::zero()));
        transcript.write_point(b0_cm.into())?;

        // msm with cq lagrange
        // let p_cm = cq_params.commit(&p_poly, Blind(E::Scalar::zero()));
        let p_cm = best_multiexp(&p_poly_coeffs, &cq_params.g1);
        transcript.write_point(p_cm.into())?;

        // Sumcheck identity:
        //      n * B(0) = N * A(0)
        //      A(0) = n * B(0) / N
        let b_at_zero = eval_polynomial(&b_poly, E::Scalar::zero());
        let a_at_zero = {
            let n_table_inv = E::Scalar::from(table.size as u64).invert().unwrap();
            let n = E::Scalar::from(n as u64);
            b_at_zero * n * n_table_inv
        };

        let mut f = self.f.to_vec();
        EvaluationDomain::ifft(
            &mut f,
            domain.get_omega_inv(),
            domain.k(),
            domain.ifft_divisor(),
        );

        let f = domain.coeff_from_vec(f);

        Ok(CommittedLogDerivative {
            b0: b0_poly,
            f,
            a_at_zero,
        })
    }
}

impl<E: MultiMillerLoop> CommittedLogDerivative<E> {
    pub(in crate::plonk) fn evaluate<
        EC: EncodedChallenge<E::G1Affine>,
        T: TranscriptWrite<E::G1Affine, EC>,
    >(
        self,
        pk: &ProvingKey<E>,
        x: ChallengeX<E::G1Affine>,
        transcript: &mut T,
    ) -> Result<Evaluated<E>, Error>
    where
        E: MultiMillerLoop + Debug,
        E::G1Affine: SerdeObject,
        E::G2Affine: SerdeObject,
    {
        let b0_eval = eval_polynomial(&self.b0, *x);
        let f_eval = eval_polynomial(&self.f, *x);

        // Hash each advice evaluation
        for eval in iter::empty()
            .chain(Some(b0_eval))
            .chain(Some(f_eval))
            .chain(Some(self.a_at_zero))
        {
            transcript.write_scalar(eval)?;
        }

        Ok(Evaluated {
            constructed: self.clone(),
        })
    }
}

impl<E: MultiMillerLoop> Evaluated<E> {
    pub(in crate::plonk) fn open<'a>(
        &'a self,
        x: ChallengeX<E::G1Affine>,
    ) -> impl Iterator<Item = ProverQuery<'a, E::G1Affine>> + Clone
    where
        E: MultiMillerLoop + Debug,
        E::G1Affine: SerdeObject,
        E::G2Affine: SerdeObject,
    {
        iter::empty()
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.constructed.b0,
                blind: Blind(E::Scalar::zero()),
            }))
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.constructed.f,
                blind: Blind(E::Scalar::zero()),
            }))
    }
}
