use std::{error::Error, fmt, marker::PhantomData};

use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::{PrimeField, Field};
use ark_poly::DenseUVPolynomial;
use ark_poly_commit::{
    PCCommitment, PCCommitterKey, PCPreparedCommitment, PCPreparedVerifierKey,
    PCRandomness, PCUniversalParams, PCVerifierKey, Polynomial, PolynomialCommitment,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::{pairing::Pairing, Group};
use rand::RngCore;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct KZGUniversalParams<G: Group + Sync> {
    degree: usize,
    ref_string: Vec<G>
}

impl <F: PrimeField, G: Group<ScalarField = F>> KZGUniversalParams<G> {
    fn new_from_secret(secret: F, max_degree: usize) -> Self {
        let generator = G::generator();
        let mut params: Self = Self {
            degree: max_degree,
            ref_string: vec![]
        };
        let mut sec_cur: F = F::one();
        for i in 0..max_degree {
            sec_cur = sec_cur.mul(secret);
            params.ref_string.push(generator * (sec_cur))
        }

        params
    }

    fn trim(&self, trim_degree: usize) -> Self {
        Self {
            degree: trim_degree,
            ref_string: self.ref_string[0..trim_degree].to_vec()
        }
    }
}

impl<G: Group> PCUniversalParams for KZGUniversalParams<G> {
    fn max_degree(&self) -> usize {
        self.degree
    }
}

impl<G: Group> PCCommitterKey for KZGUniversalParams<G> {
    fn max_degree(&self) -> usize {
        PCUniversalParams::max_degree(self)
    }

    fn supported_degree(&self) -> usize {
        PCUniversalParams::max_degree(self)
    }
}

impl<G: Group> PCVerifierKey for KZGUniversalParams<G> {
    fn max_degree(&self) -> usize {
        PCUniversalParams::max_degree(self)
    }

    fn supported_degree(&self) -> usize {
        PCCommitterKey::supported_degree(self)
    }
}

impl<G: Group> PCPreparedVerifierKey<KZGUniversalParams<G>> for KZGUniversalParams<G> {
    fn prepare(vk: &Self) -> Self {
        vk.clone()
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
struct KZGCommitment {}

impl PCCommitment for KZGCommitment {
    fn empty() -> Self {
        Self {}
    }
    fn has_degree_bound(&self) -> bool {
        false
    }
}

impl PCPreparedCommitment<Self> for KZGCommitment {
    fn prepare(comm: &KZGCommitment) -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct KZGRandomness {}

impl PCRandomness for KZGRandomness {
    fn empty() -> Self {
        Self {}
    }

    fn rand<R: RngCore>(
        num_queries: usize,
        has_degree_bound: bool,
        num_vars: Option<usize>,
        rng: &mut R,
    ) -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct KZGProof {}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct KZGBatchProof {}

impl From<Vec<KZGProof>> for KZGBatchProof {
    fn from(value: Vec<KZGProof>) -> Self {
        Self {}
    }
}

impl Into<Vec<KZGProof>> for KZGBatchProof {
    fn into(self) -> Vec<KZGProof> {
        vec![KZGProof {}]
    }
}

#[derive(Debug)]
enum ErrorType {
    BadRNGSecret,
    InvalidParameters
}
#[derive(Debug)]
struct KZGError {
    err_type: ErrorType,
}

impl KZGError {
    fn new(t: ErrorType) -> Self {
        KZGError { err_type: t }
    }
}

impl fmt::Display for KZGError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "err")
    }
}

impl Error for KZGError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self)
    }

    fn cause(&self) -> Option<&dyn Error> {
        Some(self)
    }

    fn description(&self) -> &str {
        "bc"
    }
}

impl From<ark_poly_commit::Error> for KZGError {
    fn from(value: ark_poly_commit::Error) -> Self {
        KZGError {
            err_type: ErrorType::BadRNGSecret
        }
    }
}

struct KZG<
    E: Pairing,
    P: DenseUVPolynomial<E::ScalarField, Point = E::ScalarField>,
    S: CryptographicSponge>
{
    _engine: PhantomData<E>,
    _sponge: PhantomData<S>,
    _poly: PhantomData<P>
}

impl<
    E: Pairing,
    P: DenseUVPolynomial<E::ScalarField, Point = E::ScalarField>,
    S: CryptographicSponge,
> PolynomialCommitment<E::ScalarField, P, S> for KZG<E,P,S> {
    type UniversalParams = KZGUniversalParams<E::G1>;
    type CommitterKey = KZGUniversalParams<E::G1>;
    type VerifierKey = KZGUniversalParams<E::G1>;
    type PreparedVerifierKey = KZGUniversalParams<E::G1>;
    type Commitment = KZGCommitment;
    type PreparedCommitment = KZGCommitment;
    type Randomness = KZGRandomness;
    type Proof = KZGProof;
    type BatchProof = KZGBatchProof;
    type Error = KZGError;

    fn setup<R: RngCore>(
        max_degree: usize,
        num_vars: Option<usize>,
        rng: &mut R,
    ) -> Result<Self::UniversalParams, Self::Error> {
        let mut bytes: [u8; 32] = Default::default();
        rng.fill_bytes(&mut bytes);
        let s = E::ScalarField::from_random_bytes(&bytes).ok_or(KZGError::new(ErrorType::BadRNGSecret))?;
        Ok(Self::UniversalParams::new_from_secret(s, max_degree))
    }

    fn trim(
        pp: &Self::UniversalParams,
        supported_degree: usize,
        supported_hiding_bound: usize,
        enforced_degree_bounds: Option<&[usize]>,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error> {
        if supported_degree > PCUniversalParams::max_degree(pp) {
            return Err( KZGError::new(ErrorType::InvalidParameters) )
        }

        let trimmed = pp.trim(supported_degree);
        Ok( (trimmed.clone(), trimmed) )
    }

    fn commit<'a>(
        ck: &Self::CommitterKey,
        polynomials: impl IntoIterator<Item = &'a ark_poly_commit::LabeledPolynomial<E::ScalarField, P>>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<
        (
            Vec<ark_poly_commit::LabeledCommitment<Self::Commitment>>,
            Vec<Self::Randomness>,
        ),
        Self::Error,
    >
    where
        P: 'a
    {

        todo!()
    }

    fn open<'a>(
        ck: &Self::CommitterKey,
        labeled_polynomials: impl IntoIterator<Item = &'a ark_poly_commit::LabeledPolynomial<E::ScalarField, P>>,
        commitments: impl IntoIterator<Item = &'a ark_poly_commit::LabeledCommitment<Self::Commitment>>,
        point: &'a P::Point,
        challenge_generator: &mut ark_poly_commit::challenge::ChallengeGenerator<E::ScalarField, S>,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Self::Proof, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a
    {
        todo!()
    }

    fn check<'a>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a ark_poly_commit::LabeledCommitment<Self::Commitment>>,
        point: &'a P::Point,
        values: impl IntoIterator<Item = E::ScalarField>,
        proof: &Self::Proof,
        challenge_generator: &mut ark_poly_commit::challenge::ChallengeGenerator<E::ScalarField, S>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use ark_bn254::{Bn254, Config};
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
    use ark_ec::bn::{Bn, BnConfig};
    use ark_poly::univariate::DensePolynomial;

    struct blah<E: Pairing> {
        _engine: PhantomData<E>
    }

    impl<E: Pairing> blah<E> {
        fn durr() {
            let gen = E::G1::generator();
            println!("{}",gen);
        }
    }

    type blaber = blah<Bn254>;
    type poly = DensePolynomial<<Bn254 as Pairing>::ScalarField>;
    type kzg_bn254 = KZG<Bn254, poly, PoseidonSponge<<Bn254 as Pairing>::ScalarField>>;
    

    #[test]
    fn test_eval() {
        blaber::durr();
        let params = kzg_bn254::setup(10, None, &mut rand::thread_rng());
        println!("{:?}", params);
    }
}
