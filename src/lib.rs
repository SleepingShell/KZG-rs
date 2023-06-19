use std::{error::Error, fmt, marker::PhantomData, ops::Div};

use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::{PrimeField, Field, Zero, One};
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_poly_commit::{
    PCCommitment, PCCommitterKey, PCPreparedCommitment, PCPreparedVerifierKey,
    PCRandomness, PCUniversalParams, PCVerifierKey, Polynomial, PolynomialCommitment, LabeledPolynomial, LabeledCommitment,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::{pairing::Pairing, Group};
use rand::RngCore;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct KZGUniversalParams<G1: Group + Sync, G2: Group + Sync> {
    degree: usize,
    ref_string: Vec<G1>,
    ref_string_H: Vec<G2>
}

impl <F: PrimeField, G1: Group<ScalarField = F>, G2: Group<ScalarField = F>> KZGUniversalParams<G1, G2> {
    fn new_from_secret(secret: F, max_degree: usize) -> Self {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let mut params: Self = Self {
            degree: max_degree,
            ref_string: vec![],
            ref_string_H: vec![]
        };
        params.ref_string.push(g1);
        params.ref_string_H.push(g2);

        let mut sec_cur: F = F::one();
        for i in 1..max_degree {
            sec_cur = sec_cur.mul(secret);                  //α^i
            params.ref_string.push(g1 * sec_cur);
            params.ref_string_H.push(g2 * sec_cur);
        }

        params
    }

    fn trim(&self, trim_degree: usize) -> Self {
        Self {
            degree: trim_degree,
            ref_string: self.ref_string[0..trim_degree].to_vec(),
            ref_string_H: self.ref_string_H[0..trim_degree].to_vec()
        }
    }

    fn element_at(&self, index: usize) -> G1 {
        self.ref_string[index]
    }

    fn element_at_H(&self, index: usize) -> G2 {
        self.ref_string_H[index]
    }

    /// Commit to the reference string by the sum of multiplying each coefficient by its corresponding element in
    /// the reference string. Returns the sum and degree size.
    fn commit_to_params(&self, coeffs: &[F]) -> (G1, usize) {
        let mut sum = G1::zero(); 
        let mut i = 0;
        for c in coeffs {
            sum += self.element_at(i) * c;
            i += 1;
        }

        (sum, i)
    }

}

impl<G1: Group, G2: Group> PCUniversalParams for KZGUniversalParams<G1,G2> {
    fn max_degree(&self) -> usize {
        self.degree
    }
}

impl<G1: Group, G2: Group> PCCommitterKey for KZGUniversalParams<G1,G2> {
    fn max_degree(&self) -> usize {
        PCUniversalParams::max_degree(self)
    }

    fn supported_degree(&self) -> usize {
        PCUniversalParams::max_degree(self)
    }
}

impl<G1: Group, G2: Group> PCVerifierKey for KZGUniversalParams<G1,G2> {
    fn max_degree(&self) -> usize {
        PCUniversalParams::max_degree(self)
    }

    fn supported_degree(&self) -> usize {
        PCCommitterKey::supported_degree(self)
    }
}

impl<G1: Group, G2: Group> PCPreparedVerifierKey<KZGUniversalParams<G1,G2>> for KZGUniversalParams<G1,G2> {
    fn prepare(vk: &Self) -> Self {
        vk.clone()
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
struct KZGCommitment<G: Group> {
    commit: G
}

impl<G: Group> KZGCommitment<G> {
    fn new(C: G) -> Self {
        Self {
            commit: C
        }
    }
}

impl<G: Group> PCCommitment for KZGCommitment<G> {
    fn empty() -> Self {
        Self {
            commit: G::zero()
        }
    }
    fn has_degree_bound(&self) -> bool {
        false
    }
}

impl<G: Group> PCPreparedCommitment<Self> for KZGCommitment<G> {
    fn prepare(comm: &KZGCommitment<G>) -> Self {
        comm.clone()
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
struct KZGProof<G: Group, F: PrimeField> {
    // The proof is a single point on the curve
    proof: G,

    // The evaluated challenge
    value: F
}

impl<G: Group, F: PrimeField> KZGProof<G,F> {
    fn new(proof: G, value: F) -> Self {
        Self {
            proof: proof,
            value: value
        }
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct KZGBatchProof<G: Group, F: PrimeField> {
    t1: PhantomData<G>,
    t2: PhantomData<F>
}

impl<G: Group, F: PrimeField> From< Vec<KZGProof<G,F>> > for KZGBatchProof<G, F> {
    fn from(value: Vec< KZGProof<G,F> >) -> Self {
        Self {
            t1: PhantomData,
            t2: PhantomData
        }
    }
}

impl<G: Group, F: PrimeField> Into< Vec<KZGProof<G,F>> > for KZGBatchProof<G,F> {
    fn into(self) -> Vec< KZGProof<G,F> > {
        vec![KZGProof::new(G::zero(), F::zero())]
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


impl<E,P,S> PolynomialCommitment<E::ScalarField, P, S> for KZG<E,P,S>
where
    E: Pairing,
    P: DenseUVPolynomial<E::ScalarField, Point = E::ScalarField>,
    S: CryptographicSponge,
    for<'p> &'p P: Div<&'p P, Output = P>
{
    type UniversalParams = KZGUniversalParams<E::G1, E::G2>;
    type CommitterKey = KZGUniversalParams<E::G1, E::G2>;
    type VerifierKey = KZGUniversalParams<E::G1, E::G2>;
    type PreparedVerifierKey = KZGUniversalParams<E::G1, E::G2>;
    type Commitment = KZGCommitment<E::G1>;
    type PreparedCommitment = KZGCommitment<E::G1>;
    type Randomness = KZGRandomness;
    type Proof = KZGProof<E::G1, E::ScalarField>;
    type BatchProof = KZGBatchProof<E::G1, E::ScalarField>;
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
        let mut commitments: Vec<ark_poly_commit::LabeledCommitment<Self::Commitment>> = Vec::new();
        
        for poly in polynomials.into_iter() {
            let coeffs: &[E::ScalarField] = poly.coeffs();
            let (sum, i) = ck.commit_to_params(coeffs);

            commitments.push(ark_poly_commit::LabeledCommitment::new(
                "KZG-commit".to_owned(),
                KZGCommitment::new(sum),
                Some(i)
            ));
        }
        
        Ok( (commitments, Vec::new()) )
    }

    /// Q(x) = [F(X)-F(a)] / (x-a)
    /// This method will generate proofs of the evaluation of point of all ``labeled_polynomials``
    /// 
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
        //for lpoly in labeled_polynomials.into_iter() {
            let lpoly: &LabeledPolynomial<E::ScalarField, P> = labeled_polynomials.into_iter().next().unwrap();
            let mut poly = lpoly.polynomial().clone();
            let eval = poly.evaluate(point);
            poly -= &P::from_coefficients_slice(&[eval]);

            let divisor = P::from_coefficients_slice(&[E::ScalarField::zero()-point, E::ScalarField::one()]);
            let q = &poly / &divisor;
        
            let commit = ck.commit_to_params(q.coeffs());

            Ok( KZGProof::new(commit.0, eval) )

            // It seems the Div trait does not return a remainder. The divide_with_q_and_r method does
            // This is really only relevant for batch_open
        //}
        
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
        let lcomm: &LabeledCommitment<Self::Commitment> = commitments.into_iter().next().unwrap();
        let commitment = lcomm.commitment();
        let key_sub_index = vk.element_at_H(1) - (<E::G2 as Group>::generator() * point);

        let pairing1 = E::pairing(proof.proof, key_sub_index);
        let pairing2 = E::pairing(commitment.commit - (<E::G1 as Group>::generator() * proof.value), <E::G2 as Group>::generator());

        
        Ok( pairing1 == pairing2 )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use ark_bn254::{Bn254, Config};
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge, PoseidonDefaultConfig, PoseidonDefaultConfigField};
    use ark_ec::bn::{Bn, BnConfig};
    use ark_ff::Fp256;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::{LabeledPolynomial, challenge::ChallengeGenerator};

    type F = <Bn254 as Pairing>::ScalarField;
    type S =  PoseidonSponge<<Bn254 as Pairing>::ScalarField>;
    type poly = DensePolynomial<<Bn254 as Pairing>::ScalarField>;
    type kzg_bn254 = KZG<Bn254, poly, S>;

    
    #[test]
    fn test_eval() {
        let degree_bound = 2;
        let params = kzg_bn254::setup(degree_bound, None, &mut rand::thread_rng()).unwrap();
        println!("{:?}", params);

        let (ck, vk) = kzg_bn254::trim(&params, degree_bound, 0, None).unwrap();
        
        let data = [F::from(6969), F::from(100)];
        let poly_data: poly = DenseUVPolynomial::from_coefficients_slice(&data);
        let labeled_poly = LabeledPolynomial::new(
            "my data".to_owned(),
            poly_data,
            Some(degree_bound),
            None
        );
        let (commits, _rands) = kzg_bn254::commit(&ck, &[labeled_poly], None).unwrap();
        
        println!("{:?}", commits[0].commitment());

        //let mut sponge: S = S::new(&Fp256::get_default_poseidon_parameters(2, false).unwrap());
        /*
        let point = F::from(0);
        let proof = kzg_bn254::open(
            &ck,
            &[labeled_poly],
            &commits,
            &point,
            &mut ChallengeGenerator::new_univariate(&mut sponge),
            &[KZGRandomness::empty()],
            None
        );
        */
    }
}
