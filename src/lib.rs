use anyhow::{anyhow, Result};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
pub use simpleworks::marlin::generate_rand;
pub use simpleworks::marlin::serialization::deserialize_proof;
use simpleworks::{
    gadgets::ConstraintF,
    marlin::{MarlinProof, ProvingKey, VerifyingKey},
};
use std::cell::RefCell;
use std::rc::Rc;

pub fn encrypt(
    message: Vec<u8>,
    secret_key: Vec<u8>,
    proving_key: ProvingKey,
) -> Result<(Vec<u8>, MarlinProof)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let ciphertext = encrypt_and_generate_constraints(&constraint_system, message, secret_key);

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
        &constraint_system,
        default_message_input,
        default_secret_key_input,
    );

    simpleworks::marlin::generate_proving_and_verifying_keys(&universal_srs, constraint_system)
}

fn encrypt_and_generate_constraints(
    _cs: &ConstraintSystemRef<ConstraintF>,
    _message: Vec<u8>,
    _secret_key: Vec<u8>,
) -> Vec<u8> {
    /*
        Here we do the AES encryption, generating the constraints that get all added into
        `constraint_system`.
    */

    let ciphertext = vec![];
    ciphertext
}

// TODO: Should we add decryption?
