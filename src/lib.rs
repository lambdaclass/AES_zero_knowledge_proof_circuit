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
use ark_ff::BigInteger256;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::{
    lc,
    r1cs::{ConstraintSystem, ConstraintSystemRef, LinearCombination},
};
use collect_slice::CollectSlice;
pub use simpleworks::marlin::generate_rand;
pub use simpleworks::marlin::serialization::deserialize_proof;
use simpleworks::{
    gadgets::ConstraintF,
    marlin::{MarlinProof, ProvingKey, VerifyingKey},
};
use std::cell::RefCell;
use std::rc::Rc;

const ROUND_CONSTANTS: [u32; 10] = [
    u32::from_be_bytes([0x01, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x02, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x04, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x08, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x10, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x20, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x40, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x1B, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x36, 0x00, 0x00, 0x00]),
];

pub fn encrypt(
    message: &[u8],
    secret_key: &[u8],
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

pub fn synthesize_keys() -> Result<(ProvingKey, VerifyingKey)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let universal_srs = simpleworks::marlin::generate_universal_srs(rng)?;
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let default_message_input = vec![];
    let default_secret_key_input = vec![];

    let _ciphertext = encrypt_and_generate_constraints(
        &constraint_system,
        &default_message_input,
        &default_secret_key_input,
    );

    simpleworks::marlin::generate_proving_and_verifying_keys(&universal_srs, constraint_system)
}

fn encrypt_and_generate_constraints(
    cs: &ConstraintSystemRef<ConstraintF>,
    _message: &[u8],
    _secret_key: &[u8],
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

/// This function returns the derived keys from the secret key.
/// Because AES 128 consists of 11 rounds, the result are 11 128-bit keys,
/// which we represent as 4 32-bit words, so we compute 44 32-bit elements
/// W_0, W_1, ..., W_43. The first four constitute the first round key, the
/// second four the second one, and so on.
fn derive_keys(secret_key: &[u8; 16]) -> Result<[[u8; 16]; 11]> {
    let mut result = [0u32; 44];

    let w_0 = to_u32(&secret_key[..4]);
    let w_1 = to_u32(&secret_key[4..8]);
    let w_2 = to_u32(&secret_key[8..12]);
    let w_3 = to_u32(&secret_key[12..16]);

    result[0] = w_0;
    result[1] = w_1;
    result[2] = w_2;
    result[3] = w_3;

    for i in 4..44 {
        if i % 4 == 0 {
            let substituted_and_rotated = to_u32(&substitute_word(&rotate_word(result[i - 1]))?);
            let w_i = (result[i - 4] ^ (substituted_and_rotated)) ^ ROUND_CONSTANTS[i / 4 - 1];
            result[i] = w_i;
        } else {
            result[i] = result[i - 4] ^ result[i - 1];
        }
    }

    let mut ret = [[0_u8; 16]; 11];

    for (i, elem) in result.chunks(4).enumerate() {
        elem.iter()
            .map(|e| e.to_be_bytes())
            .flat_map(|s| s)
            .collect_slice(&mut ret[i][..]);
    }

    Ok(ret)
}

fn to_u32(value: &[u8]) -> u32 {
    let array_aux: [u8; 4] = [value[0], value[1], value[2], value[3]];
    u32::from_be_bytes(array_aux)
}

fn rotate_word(input: u32) -> [u8; 4] {
    let bytes = input.to_be_bytes();
    [bytes[1], bytes[2], bytes[3], bytes[0]]
}

fn substitute_word(input: &[u8; 4]) -> Result<[u8; 4]> {
    let mut result = [0u8; 4];
    result[0] = substitute_byte(input[0])?;
    result[1] = substitute_byte(input[1])?;
    result[2] = substitute_byte(input[2])?;
    result[3] = substitute_byte(input[3])?;

    Ok(result)
}

#[test]
fn key_expansion() {
    let secret_key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let result = derive_keys(&secret_key).unwrap();

    assert_eq!(
        result[10],
        [
            0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
            0x0c, 0xa6,
        ]
    );

    println!("{:x?}", result);
}
