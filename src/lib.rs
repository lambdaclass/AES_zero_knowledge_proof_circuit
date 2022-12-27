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

fn aes_sub_bytes(input_text: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0_u8; 16];
    input_text
        .iter()
        .map(|v| substitute_byte(*v))
        .collect_slice(&mut ret[..]);

    ret
}

fn mix_columns(input: &[u8; 16]) -> [u8; 16] {
    let mul_matrix = [2_u8, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2];

    // first row
    let cell_0_0 = (mul_matrix[0] & input[0])
        ^ (mul_matrix[1] & input[4])
        ^ (mul_matrix[2] & input[8])
        ^ (mul_matrix[3] & input[12]);

    let cell_0_1 = (mul_matrix[0] & input[1])
        ^ (mul_matrix[1] & input[5])
        ^ (mul_matrix[2] & input[9])
        ^ (mul_matrix[3] & input[13]);

    let cell_0_2 = (mul_matrix[0] & input[2])
        ^ (mul_matrix[1] & input[6])
        ^ (mul_matrix[2] & input[10])
        ^ (mul_matrix[3] & input[14]);

    let cell_0_3 = (mul_matrix[0] & input[3])
        ^ (mul_matrix[1] & input[7])
        ^ (mul_matrix[2] & input[11])
        ^ (mul_matrix[3] & input[15]);

    // second row
    let cell_1_0 = (mul_matrix[4] & input[0])
        ^ (mul_matrix[5] & input[4])
        ^ (mul_matrix[6] & input[8])
        ^ (mul_matrix[7] & input[12]);

    let cell_1_1 = (mul_matrix[4] & input[1])
        ^ (mul_matrix[5] & input[5])
        ^ (mul_matrix[6] & input[9])
        ^ (mul_matrix[7] & input[13]);

    let cell_1_2 = (mul_matrix[4] & input[2])
        ^ (mul_matrix[5] & input[6])
        ^ (mul_matrix[6] & input[10])
        ^ (mul_matrix[7] & input[14]);

    let cell_1_3 = (mul_matrix[4] & input[3])
        ^ (mul_matrix[5] & input[7])
        ^ (mul_matrix[6] & input[11])
        ^ (mul_matrix[7] & input[15]);

    // third row
    let cell_2_0 = (mul_matrix[8] & input[0])
        ^ (mul_matrix[9] & input[4])
        ^ (mul_matrix[10] & input[8])
        ^ (mul_matrix[11] & input[12]);

    let cell_2_1 = (mul_matrix[8] & input[1])
        ^ (mul_matrix[9] & input[5])
        ^ (mul_matrix[10] & input[9])
        ^ (mul_matrix[11] & input[13]);

    let cell_2_2 = (mul_matrix[8] & input[2])
        ^ (mul_matrix[9] & input[6])
        ^ (mul_matrix[10] & input[10])
        ^ (mul_matrix[11] & input[14]);

    let cell_2_3 = (mul_matrix[8] & input[3])
        ^ (mul_matrix[9] & input[7])
        ^ (mul_matrix[10] & input[11])
        ^ (mul_matrix[11] & input[15]);

    // forth row
    let cell_3_0 = (mul_matrix[12] & input[0])
        ^ (mul_matrix[13] & input[4])
        ^ (mul_matrix[14] & input[8])
        ^ (mul_matrix[15] & input[12]);

    let cell_3_1 = (mul_matrix[12] & input[1])
        ^ (mul_matrix[13] & input[5])
        ^ (mul_matrix[14] & input[9])
        ^ (mul_matrix[15] & input[13]);

    let cell_3_2 = (mul_matrix[12] & input[2])
        ^ (mul_matrix[13] & input[6])
        ^ (mul_matrix[14] & input[10])
        ^ (mul_matrix[15] & input[14]);

    let cell_3_3 = (mul_matrix[12] & input[3])
        ^ (mul_matrix[13] & input[7])
        ^ (mul_matrix[14] & input[11])
        ^ (mul_matrix[15] & input[15]);

    [
        cell_0_0, cell_0_1, cell_0_2, cell_0_3, cell_1_0, cell_1_1, cell_1_2, cell_1_3, cell_2_0,
        cell_2_1, cell_2_2, cell_2_3, cell_3_0, cell_3_1, cell_3_2, cell_3_3,
    ]
}

mod test {
    #[test]
    fn test_chunk() {
        let slice = ['l', 'o', 'r', 'e', 'm'];
        let iter = slice.chunks(2);

        for v in iter {
            println!("{:?}", v);
        }
    }
}
