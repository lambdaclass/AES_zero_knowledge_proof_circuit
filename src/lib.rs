use ark_bls12_377::{Bls12_377, Fr, FrParameters, Parameters};
use ark_ec::bls12::Bls12;
use ark_ff::Fp256;
use ark_marlin::{IndexProverKey, IndexVerifierKey, Marlin, Proof, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;

pub mod aes;
pub mod ops;
pub mod prover;

pub type MarlinProof =
    Proof<Fr, MarlinKZG10<Bls12<Parameters>, DensePolynomial<Fp256<FrParameters>>>>;
