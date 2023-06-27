use std::{error::Error, fmt, marker::PhantomData, ops::Div};

use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::DenseUVPolynomial;
use ark_poly_commit::{
    LabeledCommitment, LabeledPolynomial, PCCommitment, PCCommitterKey, PCPreparedCommitment,
    PCPreparedVerifierKey, PCRandomness, PCUniversalParams, PCVerifierKey, PolynomialCommitment,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;

mod kzg_vanilla;

enum KZGType {
    Vanilla,
    VanillaHiding,
    FastAmortized
}


