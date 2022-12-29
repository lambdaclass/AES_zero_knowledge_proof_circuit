#![warn(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![warn(
    clippy::allow_attributes_without_reason,
    clippy::as_conversions,
    clippy::as_ptr_cast_mut,
    clippy::unnecessary_cast,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback,
    clippy::deref_by_slicing,
    clippy::empty_structs_with_brackets,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::indexing_slicing,
    clippy::iter_kv_map,
    clippy::manual_clamp,
    clippy::manual_filter,
    clippy::map_err_ignore,
    clippy::uninlined_format_args,
    clippy::unseparated_literal_suffix,
    clippy::unused_format_specs,
    clippy::single_char_lifetime_names,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::todo,
    clippy::try_err
)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::let_underscore_must_use
)]

pub mod aes;
pub mod helpers;
pub mod ops;

use crate::aes::substitute_byte;
use anyhow::{anyhow, Result};
use ark_relations::{
    r1cs::{ConstraintSystem, ConstraintSystemRef},
};
use helpers::traits::ToAnyhow;
pub use simpleworks::marlin::generate_rand;
pub use simpleworks::marlin::serialization::deserialize_proof;
use simpleworks::{
    gadgets::ConstraintF,
    marlin::{MarlinProof, ProvingKey, VerifyingKey},
};
use std::cell::RefCell;
use std::rc::Rc;

pub fn encrypt(
    message: &[u8],
    secret_key: &[u8; 16],
    proving_key: ProvingKey,
) -> Result<(Vec<u8>, MarlinProof)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let ciphertext = encrypt_and_generate_constraints(&constraint_system, message, secret_key)?;

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

pub fn synthesize_keys(plaintex_length: usize) -> Result<(ProvingKey, VerifyingKey)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let universal_srs = simpleworks::marlin::generate_universal_srs(rng)?;
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let default_message_input = vec![0_u8; plaintex_length];
    let default_secret_key_input = [0_u8; 16];

    let _ciphertext = encrypt_and_generate_constraints(
        &constraint_system,
        &default_message_input,
        &default_secret_key_input,
    );

    simpleworks::marlin::generate_proving_and_verifying_keys(&universal_srs, constraint_system)
}

fn encrypt_and_generate_constraints(
    cs: &ConstraintSystemRef<ConstraintF>,
    message: &[u8],
    secret_key: &[u8; 16],
) -> Result<Vec<u8>> {
    /*
        Here we do the AES encryption, generating the constraints that get all added into
        `cs`.
    */

    let mut ciphertext: Vec<u8> = Vec::new();
    let _round_keys = aes::derive_keys(secret_key);

    // TODO: Make this in 10 rounds instead of 1.
    // 1 round ECB
    for block in message.chunks(16) {
        // Step 0
        let after_add_round_key = aes::add_round_key(block, secret_key);
        // Step 1
        let after_substitute_bytes = aes::substitute_bytes(&after_add_round_key, cs)?;
        // Step 2
        let after_shift_rows = aes::shift_rows(&after_substitute_bytes, cs)?;
        // Step 3
        let after_mix_columns = aes::mix_columns(&after_shift_rows)
            .to_anyhow("Error mixing columns when encrypting")?;
        // Step 4
        // This ciphertext should represent the next round plaintext and use the round key.
        let after_add_round_key = aes::add_round_key(&after_mix_columns, secret_key);

        ciphertext.extend_from_slice(&after_add_round_key);
    }

    Ok(ciphertext)
}

fn substitute_word(input: &[u8; 4]) -> Result<[u8; 4]> {
    let mut result = [0_u8; 4];
    result[0] = substitute_byte(input[0])?;
    result[1] = substitute_byte(input[1])?;
    result[2] = substitute_byte(input[2])?;
    result[3] = substitute_byte(input[3])?;

    Ok(result)
}
