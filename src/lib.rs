use anyhow::{anyhow, Result};
use collect_slice::CollectSlice;
use ark_ff::BigInteger256;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::{
    lc,
    r1cs::{ConstraintSystem, ConstraintSystemRef, LinearCombination},
};
pub use simpleworks::marlin::generate_rand;
pub use simpleworks::marlin::serialization::deserialize_proof;
use simpleworks::{
    gadgets::ConstraintF,
    marlin::{MarlinProof, ProvingKey, VerifyingKey},
};
use std::cell::RefCell;
use std::iter::zip;
use std::rc::Rc;

pub fn encrypt(
    message: Vec<u8>,
    secret_key: Vec<u8>,
    proving_key: ProvingKey,
) -> Result<(Vec<u8>, MarlinProof)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let ciphertext =
        encrypt_and_generate_constraints(constraint_system.clone(), message, secret_key)?;

    // Here we clone the constraint system because deep down when generating
    // the proof the constraint system is consumed and it has to have one
    // reference for it to be consumed.
    let cs_clone = (*constraint_system
        .borrow()
        .ok_or("Error borrowing")
        .map_err(|e| anyhow!("{}", e))?)
    .clone();
    let cs_ref_clone = ConstraintSystemRef::CS(Rc::new(RefCell::new(cs_clone)));

    let proof = simpleworks::marlin::generate_proof(cs_ref_clone, proving_key, rng)?;

    Ok((ciphertext, proof))
}

pub fn verify_encryption(verifying_key: VerifyingKey, proof: &MarlinProof) -> Result<bool> {
    simpleworks::marlin::verify_proof(
        verifying_key,
        &[],
        proof,
        &mut simpleworks::marlin::generate_rand(),
    )
}

pub fn synthetize_keys() -> Result<(ProvingKey, VerifyingKey)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let universal_srs = simpleworks::marlin::generate_universal_srs(rng)?;
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let default_message_input = vec![];
    let default_secret_key_input = vec![];

    let _ciphertext = encrypt_and_generate_constraints(
        constraint_system.clone(),
        default_message_input,
        default_secret_key_input,
    );

    simpleworks::marlin::generate_proving_and_verifying_keys(&universal_srs, constraint_system)
}

fn encrypt_and_generate_constraints(
    cs: ConstraintSystemRef<ConstraintF>,
    _message: Vec<u8>,
    _secret_key: Vec<u8>,
) -> Result<Vec<u8>> {
    /*
        Here we do the AES encryption, generating the constraints that get all added into
        `cs`.
    */

    let a = cs.new_witness_variable(|| Ok(ConstraintF::new(BigInteger256::new([1, 0, 0, 0]))))?;

    let b = cs.new_witness_variable(|| Ok(ConstraintF::new(BigInteger256::new([1, 0, 0, 0]))))?;

    let difference: LinearCombination<ConstraintF> = lc!() + a - b;
    let true_variable = &Boolean::<ConstraintF>::TRUE;
    cs.enforce_constraint(difference, true_variable.lc(), lc!())?;

    let ciphertext = vec![];
    Ok(ciphertext)
}

/// Performs the xor bit by bit between the input_text and the key
fn aes_add_round_key(input_text: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0_u8; 16];

    let _ = zip(input_text, key)
        .map(|(cell_i, key_i)| cell_i ^ key_i)
        .collect_slice(&mut ret[..]);

    ret
}
