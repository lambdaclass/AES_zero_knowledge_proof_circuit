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
use helpers::traits::ToAnyhow;
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

#[allow(unused)]
/// Performs the xor bit by bit between the `input_text` and the key
fn aes_add_round_key(input_text: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0_u8; 16];

    let _ = zip(input_text, key)
        .map(|(cell_i, key_i)| cell_i ^ key_i)
        .collect_slice(&mut ret[..]);

    ret
}

fn aes_sub_bytes(input_text: &[u8; 16]) -> Result<[u8; 16]> {
    let mut ret = [0_u8; 16];
    input_text
        .iter()
        .enumerate()
        .try_for_each(|(i, byte_to_substitute)| {
            let substituted_byte = ret.get_mut(i).to_anyhow("Error getting byte")?;
            *substituted_byte = substitute_byte(*byte_to_substitute)?;
            Ok::<_, anyhow::Error>(())
        })?;
    Ok(ret)
}

fn gmix_column(input: &[u8; 4]) -> [u8; 4] {
    let mut b: [u8; 4] = [0; 4];
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */

    for (i, c) in input.iter().enumerate() {
        let h = (c >> 7) & 1; /* arithmetic right shift, thus shifting in either zeros or ones */
        b[i] = c << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[i] ^= h * 0x1B; /* Rijndael's Galois field */
    }

    [
        b[0] ^ input[3] ^ input[2] ^ b[1] ^ input[1],
        b[1] ^ input[0] ^ input[3] ^ b[2] ^ input[2],
        b[2] ^ input[1] ^ input[0] ^ b[3] ^ input[3],
        b[3] ^ input[2] ^ input[1] ^ b[0] ^ input[0],
    ]
}

fn mix_columns(input: &[u8; 16]) -> [u8; 16] {
    let mut ret: [u8; 16] = [0; 16];
    for (pos, column) in input.chunks(4).enumerate() {
        let column_aux = [column[0], column[1], column[2], column[3]];
        let column_ret = gmix_column(&column_aux);

        // put column_ret in ret:
        ret[pos * 4] = column_ret[0];
        ret[pos * 4 + 1] = column_ret[1];
        ret[pos * 4 + 2] = column_ret[2];
        ret[pos * 4 + 3] = column_ret[3];
    }

    ret
}

#[cfg(test)]
mod test {
    use crate::{gmix_column, mix_columns};

    #[test]
    fn test_gcolumn_mix() {
        let input: [u8; 4] = [0xdb, 0x13, 0x53, 0x45];
        let ret = gmix_column(&input);
        println!("{:?}", ret);

        let input2: [u8; 4] = [0xd4, 0xbf, 0x5d, 0x30];
        let ret2 = gmix_column(&input2);
        println!("{:?}", ret2);

        let input3: [u8; 4] = [0xe0, 0xb4, 0x52, 0xae];
        let ret3 = gmix_column(&input3);
        println!("{:?}", ret3);
    }

    // cn = [u8; 4] -> u32 -> [u8; 4];
    // [2, 1, 1, 3] [c0] = [2c0 + c1 + c2 + 3c3]
    // [3, 2, 1, 1] [c1] = [3c0 + 2c1 + c2 + c3]
    // [1, 3, 2, 1] [c2] = [c0 + 3c1 + 2c2 + c3]
    // [1, 1, 3, 2] [c3] = [c0 + c1 + 3c2 + 2c3]
    #[test]
    fn test_one_round_column_mix() {
        let value_to_mix: [u8; 16] = [
            0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
            0x98, 0xe5,
        ];
        let expected_mixed_value: [u8; 16] = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
            0x26, 0x4c,
        ];

        let mixed_column_vector = mix_columns(&value_to_mix);

        assert_eq!(expected_mixed_value, mixed_column_vector);
    }
}
