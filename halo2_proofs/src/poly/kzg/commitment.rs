use crate::arithmetic::{
    best_fft, best_multiexp, g_to_lagrange, parallelize, CurveAffine, CurveExt, FieldExt, Group,
};
use crate::helpers::SerdeCurveAffine;
use crate::poly::commitment::{Blind, CommitmentScheme, Params, ParamsProver, ParamsVerifier, MSM};
use crate::poly::{Coeff, LagrangeCoeff, Polynomial};
use crate::SerdeFormat;

use ff::{BatchInvert, Field, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, Group as _};
use halo2curves::pairing::Engine;
use rand_core::{OsRng, RngCore};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul, MulAssign};

use std::io;

use super::msm::MSMKZG;

pub fn is_pow_2(x: usize) -> bool {
    (x & (x - 1)) == 0
}

fn log2(x: usize) -> u32 {
    (usize::BITS - 1) - x.leading_zeros()
}

/// These are the public parameters for the polynomial commitment scheme.
#[derive(Debug, Clone)]
pub struct ParamsKZG<E: Engine> {
    pub(crate) k: u32,
    pub(crate) n: u64,
    pub(crate) g: Vec<E::G1Affine>,
    // TODO: make pub(crate)
    pub g_lagrange: Vec<E::G1Affine>,
    pub(crate) g2: E::G2Affine,
    pub(crate) s_g2: E::G2Affine,
}

#[derive(Debug, Clone)]
pub struct TableSRS<E: Engine> {
    pub(crate) g1: Vec<E::G1Affine>,
    pub(crate) g1_lagrange: Vec<E::G1Affine>,
    pub(crate) g_lagrange_opening_at_0: Vec<E::G1Affine>,
    pub(crate) g2: Vec<E::G2Affine>,
}

impl<E: Engine> TableSRS<E> {
    /// Return G1
    pub fn g1(&self) -> &[E::G1Affine] {
        &self.g1
    }

    /// Return G2
    pub fn g2(&self) -> &[E::G2Affine] {
        &self.g2
    }

    /// Return G1 lagrange
    pub fn g1_lagrange(&self) -> &[E::G1Affine] {
        &self.g1_lagrange
    }

    /// Return G1 lagrange openings at 0
    pub fn g_lagrange_opening_at_0(&self) -> &[E::G1Affine] {
        &self.g_lagrange_opening_at_0
    }
}

impl<E: Engine> TableSRS<E> {
    /// FOR TESTING PURPOSES
    pub fn setup_from_toxic_waste(max_g1_power: usize, max_g2_power: usize, s: E::Scalar) -> Self {
        let g1_len = (max_g1_power + 1) as usize;
        let g2_len = (max_g2_power + 1) as usize;
        assert!(is_pow_2(g1_len));

        // Calculate g = [G1, [s] G1, [s^2] G1, ..., [s^(n-1)] G1] in parallel.
        let g1_gen = E::G1Affine::generator();
        let g2_gen = E::G2Affine::generator();

        let mut g_projective = vec![E::G1::group_zero(); g1_len as usize];

        // TODO: consider to merge this two parallelize
        parallelize(&mut g_projective, |g, start| {
            let mut current_g: E::G1 = g1_gen.into();

            current_g *= s.pow_vartime(&[start as u64]);
            for g in g.iter_mut() {
                *g = current_g;
                current_g *= s;
            }
        });

        let mut g2_projective = vec![E::G2::group_zero(); g2_len as usize];
        parallelize(&mut g2_projective, |g, start| {
            let mut current_g: E::G2 = g2_gen.into();

            current_g *= s.pow_vartime(&[start as u64]);
            for g in g.iter_mut() {
                *g = current_g;
                current_g *= s;
            }
        });

        let g1 = {
            let mut g1 = vec![E::G1Affine::identity(); g1_len as usize];
            parallelize(&mut g1, |g1, starts| {
                E::G1::batch_normalize(&g_projective[starts..(starts + g1.len())], g1);
            });
            g1
        };

        let g2 = {
            let mut g2 = vec![E::G2Affine::identity(); g2_len as usize];
            parallelize(&mut g2, |g2, starts| {
                E::G2::batch_normalize(&g2_projective[starts..(starts + g2.len())], g2);
            });
            g2
        };

        let mut g_lagrange_projective = vec![E::G1::group_zero(); g1_len];
        let mut root = E::Scalar::ROOT_OF_UNITY_INV.invert().unwrap();

        let k = log2(g1_len); // we asserted that g1_len is pow_2
        for _ in k..E::Scalar::S {
            root = root.square();
        }

        let n_inv = Option::<E::Scalar>::from(E::Scalar::from(g1_len as u64).invert())
            .expect("inversion should be ok for n pow2");

        // x^N - 1
        let multiplier = (s.pow_vartime(&[g1_len as u64]) - E::Scalar::one()) * n_inv;
        parallelize(&mut g_lagrange_projective, |g, start| {
            for (idx, g) in g.iter_mut().enumerate() {
                let offset = start + idx;
                let root_pow = root.pow_vartime(&[offset as u64]);
                let scalar = multiplier * root_pow * (s - root_pow).invert().unwrap();
                *g = g1_gen * scalar;
            }
        });

        let g1_lagrange = {
            let mut g_lagrange = vec![E::G1Affine::identity(); g1_len];
            parallelize(&mut g_lagrange, |g_lagrange, starts| {
                E::G1::batch_normalize(
                    &g_lagrange_projective[starts..(starts + g_lagrange.len())],
                    g_lagrange,
                );
            });
            drop(g_lagrange_projective);
            g_lagrange
        };

        //   [(L_i(x) - L_i(0)) / x]_1
        // = omega^{-i} * [L_i(x)]_1 - (1 / N) * [x^{N-1}]_1
        let mut roots_of_unity_inv: Vec<E::Scalar> =
            std::iter::successors(Some(E::Scalar::one()), |p| Some(*p * root))
                .take(g1_len)
                .collect();
        roots_of_unity_inv.iter_mut().batch_invert();

        // [x^{N - 1}]_1 * (1 / N)
        let last_power_scaled = *g1.last().unwrap() * n_inv;
        let g_lagrange_opening_at_0: Vec<E::G1Affine> = g1_lagrange
            .iter()
            .zip(roots_of_unity_inv.iter())
            .map(|(&l_i, w_inv_i)| (l_i * w_inv_i - last_power_scaled).into())
            .collect();

        Self {
            g1,
            g1_lagrange,
            g_lagrange_opening_at_0,
            g2,
        }
    }
}
/// Umbrella commitment scheme construction for all KZG variants
#[derive(Debug)]
pub struct KZGCommitmentScheme<E: Engine> {
    _marker: PhantomData<E>,
}

impl<E: Engine + Debug> CommitmentScheme for KZGCommitmentScheme<E>
where
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type Scalar = E::Scalar;
    type Curve = E::G1Affine;

    type ParamsProver = ParamsKZG<E>;
    type ParamsVerifier = ParamsVerifierKZG<E>;

    fn new_params<R: RngCore>(k: u32, rng: &mut R) -> Self::ParamsProver {
        ParamsKZG::new(k, rng)
    }

    fn read_params<R: io::Read>(reader: &mut R) -> io::Result<Self::ParamsProver> {
        ParamsKZG::read(reader)
    }
}

impl<E: Engine + Debug> ParamsKZG<E> {
    /// Initializes parameters for the curve, draws toxic secret from given rng.
    /// MUST NOT be used in production.
    pub fn setup_from_toxic_waste(k: u32, s: E::Scalar) -> Self {
        // Largest root of unity exponent of the Engine is `2^E::Scalar::S`, so we can
        // only support FFTs of polynomials below degree `2^E::Scalar::S`.
        assert!(k <= E::Scalar::S);
        let n: u64 = 1 << k;

        // Calculate g = [G1, [s] G1, [s^2] G1, ..., [s^(n-1)] G1] in parallel.
        let g1 = E::G1Affine::generator();

        let mut g_projective = vec![E::G1::identity(); n as usize];
        parallelize(&mut g_projective, |g, start| {
            let mut current_g: E::G1 = g1.into();
            current_g *= s.pow_vartime(&[start as u64]);
            for g in g.iter_mut() {
                *g = current_g;
                current_g *= s;
            }
        });

        let g = {
            let mut g = vec![E::G1Affine::identity(); n as usize];
            parallelize(&mut g, |g, starts| {
                E::G1::batch_normalize(&g_projective[starts..(starts + g.len())], g);
            });
            g
        };

        let mut g_lagrange_projective = vec![E::G1::identity(); n as usize];
        let mut root = E::Scalar::ROOT_OF_UNITY_INV.invert().unwrap();
        for _ in k..E::Scalar::S {
            root = root.square();
        }
        let n_inv = Option::<E::Scalar>::from(E::Scalar::from(n).invert())
            .expect("inversion should be ok for n = 1<<k");
        let multiplier = (s.pow_vartime(&[n as u64]) - E::Scalar::one()) * n_inv;
        parallelize(&mut g_lagrange_projective, |g, start| {
            for (idx, g) in g.iter_mut().enumerate() {
                let offset = start + idx;
                let root_pow = root.pow_vartime(&[offset as u64]);
                let scalar = multiplier * root_pow * (s - root_pow).invert().unwrap();
                *g = g1 * scalar;
            }
        });

        let g_lagrange = {
            let mut g_lagrange = vec![E::G1Affine::identity(); n as usize];
            parallelize(&mut g_lagrange, |g_lagrange, starts| {
                E::G1::batch_normalize(
                    &g_lagrange_projective[starts..(starts + g_lagrange.len())],
                    g_lagrange,
                );
            });
            drop(g_lagrange_projective);
            g_lagrange
        };

        let g2 = <E::G2Affine as PrimeCurveAffine>::generator();
        let s_g2 = (g2 * s).into();

        Self {
            k,
            n,
            g,
            g_lagrange,
            g2,
            s_g2,
        }
    }

    /// Initializes parameters for the curve, draws toxic secret from given rng.
    /// MUST NOT be used in production.
    pub fn setup<R: RngCore>(k: u32, rng: R) -> Self {
        // Largest root of unity exponent of the Engine is `2^E::Scalar::S`, so we can
        // only support FFTs of polynomials below degree `2^E::Scalar::S`.
        assert!(k <= E::Scalar::S);
        let n: u64 = 1 << k;

        // Calculate g = [G1, [s] G1, [s^2] G1, ..., [s^(n-1)] G1] in parallel.
        let g1 = E::G1Affine::generator();
        let s = <E::Scalar>::random(rng);

        let mut g_projective = vec![E::G1::identity(); n as usize];
        parallelize(&mut g_projective, |g, start| {
            let mut current_g: E::G1 = g1.into();
            current_g *= s.pow_vartime(&[start as u64]);
            for g in g.iter_mut() {
                *g = current_g;
                current_g *= s;
            }
        });

        let g = {
            let mut g = vec![E::G1Affine::identity(); n as usize];
            parallelize(&mut g, |g, starts| {
                E::G1::batch_normalize(&g_projective[starts..(starts + g.len())], g);
            });
            g
        };

        let mut g_lagrange_projective = vec![E::G1::identity(); n as usize];
        let mut root = E::Scalar::ROOT_OF_UNITY_INV.invert().unwrap();
        for _ in k..E::Scalar::S {
            root = root.square();
        }
        let n_inv = Option::<E::Scalar>::from(E::Scalar::from(n).invert())
            .expect("inversion should be ok for n = 1<<k");
        let multiplier = (s.pow_vartime(&[n as u64]) - E::Scalar::one()) * n_inv;
        parallelize(&mut g_lagrange_projective, |g, start| {
            for (idx, g) in g.iter_mut().enumerate() {
                let offset = start + idx;
                let root_pow = root.pow_vartime(&[offset as u64]);
                let scalar = multiplier * root_pow * (s - root_pow).invert().unwrap();
                *g = g1 * scalar;
            }
        });

        let g_lagrange = {
            let mut g_lagrange = vec![E::G1Affine::identity(); n as usize];
            parallelize(&mut g_lagrange, |g_lagrange, starts| {
                E::G1::batch_normalize(
                    &g_lagrange_projective[starts..(starts + g_lagrange.len())],
                    g_lagrange,
                );
            });
            drop(g_lagrange_projective);
            g_lagrange
        };

        let g2 = <E::G2Affine as PrimeCurveAffine>::generator();
        let s_g2 = (g2 * s).into();

        Self {
            k,
            n,
            g,
            g_lagrange,
            g2,
            s_g2,
        }
    }

    /// Returns gernerator on G2
    pub fn g2(&self) -> E::G2Affine {
        self.g2
    }

    /// Returns first power of secret on G2
    pub fn s_g2(&self) -> E::G2Affine {
        self.s_g2
    }

    /// Returns g1 generators
    pub fn g1_srs(&self) -> &[E::G1Affine] {
        &self.g
    }

    /// Writes parameters to buffer
    pub fn write_custom<W: io::Write>(&self, writer: &mut W, format: SerdeFormat)
    where
        E::G1Affine: SerdeCurveAffine,
        E::G2Affine: SerdeCurveAffine,
    {
        writer.write_all(&self.k.to_le_bytes()).unwrap();
        for el in self.g.iter() {
            el.write(writer, format);
        }
        for el in self.g_lagrange.iter() {
            el.write(writer, format);
        }
        self.g2.write(writer, format);
        self.s_g2.write(writer, format);
    }

    /// Reads params from a buffer.
    pub fn read_custom<R: io::Read>(reader: &mut R, format: SerdeFormat) -> Self
    where
        E::G1Affine: SerdeCurveAffine,
        E::G2Affine: SerdeCurveAffine,
    {
        let mut k = [0u8; 4];
        reader.read_exact(&mut k[..]).unwrap();
        let k = u32::from_le_bytes(k);
        let n = 1 << k;

        let (g, g_lagrange) = match format {
            SerdeFormat::Processed => {
                use group::GroupEncoding;
                let load_points_from_file_parallelly =
                    |reader: &mut R| -> Vec<Option<E::G1Affine>> {
                        let mut points_compressed =
                            vec![<<E as Engine>::G1Affine as GroupEncoding>::Repr::default(); n];
                        for points_compressed in points_compressed.iter_mut() {
                            reader.read_exact((*points_compressed).as_mut()).unwrap();
                        }

                        let mut points = vec![Option::<E::G1Affine>::None; n];
                        parallelize(&mut points, |points, chunks| {
                            for (i, point) in points.iter_mut().enumerate() {
                                *point = Option::from(E::G1Affine::from_bytes(
                                    &points_compressed[chunks + i],
                                ));
                            }
                        });
                        points
                    };

                let g = load_points_from_file_parallelly(reader);
                let g: Vec<<E as Engine>::G1Affine> = g
                    .iter()
                    .map(|point| point.unwrap_or_else(|| panic!("invalid point encoding")))
                    .collect();
                let g_lagrange = load_points_from_file_parallelly(reader);
                let g_lagrange: Vec<<E as Engine>::G1Affine> = g_lagrange
                    .iter()
                    .map(|point| point.unwrap_or_else(|| panic!("invalid point encoding")))
                    .collect();
                (g, g_lagrange)
            }
            SerdeFormat::RawBytes => {
                let g = (0..n)
                    .map(|_| <E::G1Affine as SerdeCurveAffine>::read(reader, format))
                    .collect();
                let g_lagrange = (0..n)
                    .map(|_| <E::G1Affine as SerdeCurveAffine>::read(reader, format))
                    .collect();
                (g, g_lagrange)
            }
            SerdeFormat::RawBytesUnchecked => {
                // avoid try branching for performance
                let g = (0..n)
                    .map(|_| <E::G1Affine as SerdeCurveAffine>::read(reader, format))
                    .collect::<Vec<_>>();
                let g_lagrange = (0..n)
                    .map(|_| <E::G1Affine as SerdeCurveAffine>::read(reader, format))
                    .collect::<Vec<_>>();
                (g, g_lagrange)
            }
        };

        let g2 = E::G2Affine::read(reader, format);
        let s_g2 = E::G2Affine::read(reader, format);

        Self {
            k,
            n: n as u64,
            g,
            g_lagrange,
            g2,
            s_g2,
        }
    }
}

// TODO: see the issue at https://github.com/appliedzkp/halo2/issues/45
// So we probably need much smaller verifier key. However for new bases in g1 should be in verifier keys.
/// KZG multi-open verification parameters
pub type ParamsVerifierKZG<C> = ParamsKZG<C>;

impl<'params, E: Engine + Debug> Params<'params, E::G1Affine> for ParamsKZG<E>
where
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type MSM = MSMKZG<E>;

    fn k(&self) -> u32 {
        self.k
    }

    fn n(&self) -> u64 {
        self.n
    }

    fn downsize(&mut self, k: u32) {
        assert!(k <= self.k);

        self.k = k;
        self.n = 1 << k;

        self.g.truncate(self.n as usize);
        self.g_lagrange = g_to_lagrange(self.g.iter().map(|g| g.to_curve()).collect(), k);
    }

    fn empty_msm(&'params self) -> MSMKZG<E> {
        MSMKZG::new()
    }

    fn commit_lagrange(
        &self,
        poly: &Polynomial<E::Scalar, LagrangeCoeff>,
        _: Blind<E::Scalar>,
    ) -> E::G1 {
        let size = poly.len();
        assert!(self.n() >= size as u64);
        best_multiexp(poly, &self.g_lagrange[0..size])
    }

    /// Writes params to a buffer.
    fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        Ok(self.write_custom(writer, SerdeFormat::RawBytesUnchecked))
    }

    /// Reads params from a buffer.
    fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        Ok(Self::read_custom(reader, SerdeFormat::RawBytesUnchecked))
    }
}

impl<'params, E: Engine + Debug> ParamsVerifier<'params, E::G1Affine> for ParamsKZG<E>
where
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
}

impl<'params, E: Engine + Debug> ParamsProver<'params, E::G1Affine> for ParamsKZG<E>
where
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type ParamsVerifier = ParamsVerifierKZG<E>;

    fn verifier_params(&'params self) -> &'params Self::ParamsVerifier {
        self
    }

    fn new<R: RngCore>(k: u32, rng: &mut R) -> Self {
        unreachable!()
    }

    fn commit(&self, poly: &Polynomial<E::Scalar, Coeff>, _: Blind<E::Scalar>) -> E::G1 {
        let size = poly.len();
        assert!(self.n() >= size as u64);
        best_multiexp(poly, &self.g[0..size])
    }

    fn get_g(&self) -> &[E::G1Affine] {
        &self.g
    }
}

#[cfg(test)]
mod test {
    use crate::arithmetic::{
        best_fft, best_multiexp, parallelize, CurveAffine, CurveExt, FieldExt, Group,
    };
    use crate::poly::commitment::ParamsProver;
    use crate::poly::commitment::{Blind, CommitmentScheme, Params, MSM};
    use crate::poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG};
    use crate::poly::kzg::msm::MSMKZG;
    use crate::poly::kzg::multiopen::ProverSHPLONK;
    use crate::poly::{Coeff, LagrangeCoeff, Polynomial};

    use ff::{Field, PrimeField};
    use group::{prime::PrimeCurveAffine, Curve, Group as _};
    use halo2curves::bn256::G1Affine;
    use std::marker::PhantomData;
    use std::ops::{Add, AddAssign, Mul, MulAssign};

    use std::io;

    #[test]
    fn test_commit_lagrange() {
        const K: u32 = 6;

        use rand_core::OsRng;

        use crate::poly::EvaluationDomain;
        use halo2curves::bn256::{Bn256, Fr};

        let params = ParamsKZG::<Bn256>::new(K, &mut OsRng);
        let domain = EvaluationDomain::new(1, K);

        let mut a = domain.empty_lagrange();

        for (i, a) in a.iter_mut().enumerate() {
            *a = Fr::from(i as u64);
        }

        let b = domain.lagrange_to_coeff(a.clone());

        let alpha = Blind(Fr::random(OsRng));

        assert_eq!(params.commit(&b, alpha), params.commit_lagrange(&a, alpha));
    }

    #[test]
    fn test_parameter_serialisation_roundtrip() {
        const K: u32 = 4;

        use ff::Field;
        use rand_core::OsRng;

        use super::super::commitment::{Blind, Params};
        use crate::arithmetic::{eval_polynomial, FieldExt};
        use crate::halo2curves::bn256::{Bn256, Fr};
        use crate::poly::EvaluationDomain;

        let params0 = ParamsKZG::<Bn256>::new(K, &mut OsRng);
        let mut data = vec![];
        <ParamsKZG<_> as Params<_>>::write(&params0, &mut data).unwrap();
        let params1: ParamsKZG<Bn256> = Params::read::<_>(&mut &data[..]).unwrap();

        assert_eq!(params0.k, params1.k);
        assert_eq!(params0.n, params1.n);
        assert_eq!(params0.g.len(), params1.g.len());
        assert_eq!(params0.g_lagrange.len(), params1.g_lagrange.len());

        assert_eq!(params0.g, params1.g);
        assert_eq!(params0.g_lagrange, params1.g_lagrange);
        assert_eq!(params0.g2, params1.g2);
        assert_eq!(params0.s_g2, params1.s_g2);
    }
}
