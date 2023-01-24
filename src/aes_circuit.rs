use crate::helpers::{self, traits::ToAnyhow};
use anyhow::{ensure, Result};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean},
    select::CondSelectGadget,
    ToBitsGadget, uint8::UInt8, uint32::UInt32,
};
use ark_relations::r1cs::ConstraintSystemRef;
use collect_slice::CollectSlice;
use simpleworks::{
    gadgets::{
        traits::{BitShiftGadget, ByteRotationGadget}
    },
};

/// This function returns the derived keys from the secret key.
/// Because AES 128 consists of 11 rounds, the result are 11 128-bit keys,
/// which we represent as 4 32-bit words, so we compute 44 32-bit elements
/// W_0, W_1, ..., W_43. The first four constitute the first round key, the
/// second four the second one, and so on.
pub fn derive_keys<F: PrimeField>(
    secret_key: &[UInt8::<F>],
    lookup_table: &[UInt8::<F>],
    constraint_system: ConstraintSystemRef<F>,
) -> Result<Vec<Vec<UInt8::<F>>>> {
    let round_constants: [UInt32::<F>; 10] = [
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x01, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x02, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x04, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x08, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x10, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x20, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x40, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x1B, 0x00, 0x00, 0x00]),
        )?,
        UInt32::<F>::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x36, 0x00, 0x00, 0x00]),
        )?,
    ];

    let mut result: Vec<UInt32<F>> = Vec::with_capacity(44);

    result.push(to_u32(secret_key.get(..4).to_anyhow(
        "Error getting secret key slice when converting to u32",
    )?)?);
    result.push(to_u32(secret_key.get(4..8).to_anyhow(
        "Error getting secret key slice when converting to u32",
    )?)?);
    result.push(to_u32(secret_key.get(8..12).to_anyhow(
        "Error getting secret key slice when converting to u32",
    )?)?);
    result.push(to_u32(secret_key.get(12..16).to_anyhow(
        "Error getting secret key slice when converting to u32",
    )?)?);

    for i in 4..44 {
        if i % 4 == 0 {
            let substituted_and_rotated = to_u32(&substitute_word(
                &rotate_word(
                    result.get(i - 1).to_anyhow("Error rotating word")?,
                    constraint_system.clone(),
                )?,
                lookup_table,
            )?)?;

            let mut res = (result
                .get(i - 4)
                .to_anyhow("Error getting elem")?
                .xor(&substituted_and_rotated))?;

            res = res.xor(
                round_constants
                    .get(i / 4 - 1)
                    .to_anyhow("Error getting elem")?,
            )?;

            result.push(res);
        } else {
            let res = result
                .get(i - 4)
                .to_anyhow("Error getting elem")?
                .xor(result.get(i - 1).to_anyhow("Error getting elem")?)?;

            result.push(res);
        }
    }

    let mut ret: Vec<Vec<UInt8::<F>>> = vec![];

    for elem in result.chunks_mut(4) {
        let mut round_key = vec![];
        for u32_value in elem {
            let bytes = to_bytes_be(u32_value);
            for byte in bytes {
                round_key.push(byte);
            }
        }
        ret.push(round_key);
    }

    Ok(ret)
}

fn substitute_word<F: PrimeField>(
    input: &[UInt8::<F>],
    lookup_table: &[UInt8::<F>],
) -> Result<[UInt8::<F>; 4]> {
    ensure!(
        input.len() == 4,
        "Input to substitute_word must be 4 bytes, got {}",
        input.len()
    );

    Ok([
        substitute_byte(
            input
                .get(0)
                .to_anyhow("Error getting input value 0 when substituting word")?,
            lookup_table,
        )?,
        substitute_byte(
            input
                .get(1)
                .to_anyhow("Error getting input value 1 when substituting word")?,
            lookup_table,
        )?,
        substitute_byte(
            input
                .get(2)
                .to_anyhow("Error getting input value 2 when substituting word")?,
            lookup_table,
        )?,
        substitute_byte(
            input
                .get(3)
                .to_anyhow("Error getting input value 3 when substituting word")?,
            lookup_table,
        )?,
    ])
}

fn rotate_word<F: PrimeField>(
    input: &UInt32::<F>,
    constraint_system: ConstraintSystemRef<F>,
) -> Result<[UInt8::<F>; 4]> {
    let mut word_to_rotate = [
        UInt8::<F>::constant(0),
        UInt8::<F>::constant(0),
        UInt8::<F>::constant(0),
        UInt8::<F>::constant(0),
    ];

    for (word_to_rotate_byte, input_byte) in word_to_rotate.iter_mut().zip(to_bytes_be(input)) {
        *word_to_rotate_byte = input_byte;
    }

    word_to_rotate.rotate_left(1, constraint_system)
}

// It's either this or forking `r1cs-std`.
fn to_bytes_be<F: PrimeField>(input: &UInt32::<F>) -> Vec<UInt8::<F>> {
    let mut bits = input.to_bits_le();
    bits.reverse();

    bits.chunks_mut(8)
        .map(|chunk| {
            chunk.reverse();
            UInt8::<F>::from_bits_le(chunk)
        })
        .collect()
}

fn to_u32<F: PrimeField>(value: &[UInt8::<F>]) -> Result<UInt32::<F>> {
    ensure!(value.len() == 4, "Invalid length for u32");

    let mut bits = [Boolean::<F>::FALSE; 32];
    value
        .iter()
        .rev()
        .filter_map(|elem| elem.to_bits_le().ok())
        .flatten()
        .collect_slice(&mut bits);

    Ok(UInt32::<F>::from_bits_le(&bits))
}

pub fn add_round_key<F: PrimeField>(input: &[UInt8::<F>], round_key: &[UInt8::<F>]) -> Result<Vec<UInt8::<F>>> {
    ensure!(
        input.len() == 16,
        "Input must be 16 bytes length when adding round key"
    );
    ensure!(
        round_key.len() == 16,
        "Round key must be 16 bytes length when adding round key"
    );

    let output = input
        .iter()
        .zip(round_key)
        .filter_map(|(input_text_byte, round_key_byte)| {
            input_text_byte
                .xor(round_key_byte)
                .to_anyhow("Error adding round key")
                .ok()
        })
        .collect::<Vec<UInt8::<F>>>();

    ensure!(output.len() == 16, "Error adding round key");

    Ok(output)
}

fn substitute_byte<F: PrimeField>(byte: &UInt8::<F>, lookup_table: &[UInt8::<F>]) -> Result<UInt8::<F>> {
    Ok(UInt8::<F>::conditionally_select_power_of_two_vector(
        &byte.to_bits_be()?,
        lookup_table,
    )?)
}

pub fn substitute_bytes<F: PrimeField>(
    bytes: &[UInt8::<F>],
    lookup_table: &[UInt8::<F>],
) -> Result<Vec<UInt8::<F>>> {
    ensure!(
        bytes.len() == 16,
        "Input must be 16 bytes length when substituting bytes"
    );

    let mut substituted_bytes: Vec<UInt8<F>> = vec![];
    for byte in bytes {
        substituted_bytes.push(substitute_byte(byte, lookup_table)?);
    }

    ensure!(substituted_bytes.len() == 16, "Error substituting bytes");
    Ok(substituted_bytes)
}

pub fn shift_rows<F: PrimeField>(
    bytes: &[UInt8::<F>],
    constraint_system: ConstraintSystemRef<F>,
) -> Option<Vec<UInt8::<F>>> {
    // Turn the bytes into the 4x4 AES state matrix.
    // The matrix is represented by a 2D array,
    // where each array is a row.
    // That is, let's suppose that the flattened_bytes variable
    // is formed by the bytes
    // [b0, ..., b15]
    // Then the AES state matrix will look like this:
    // b0, b4, b8, b12,
    // b1, b5, b9, b13,
    // b2, b6, b10, b14,
    // b3, b7, b11, b15
    // We shift each row, then return back the result as the flattened version.

    let first_row = [
        bytes.get(0)?.clone(),
        bytes.get(4)?.clone(),
        bytes.get(8)?.clone(),
        bytes.get(12)?.clone(),
    ];
    let second_row = [
        bytes.get(1)?.clone(),
        bytes.get(5)?.clone(),
        bytes.get(9)?.clone(),
        bytes.get(13)?.clone(),
    ];
    let third_row = [
        bytes.get(2)?.clone(),
        bytes.get(6)?.clone(),
        bytes.get(10)?.clone(),
        bytes.get(14)?.clone(),
    ];
    let fourth_row = [
        bytes.get(3)?.clone(),
        bytes.get(7)?.clone(),
        bytes.get(11)?.clone(),
        bytes.get(15)?.clone(),
    ];

    let rotated_second_row = second_row.rotate_left(1, constraint_system.clone()).ok()?;
    let rotated_third_row = third_row.rotate_left(2, constraint_system.clone()).ok()?;
    let rotated_fourth_row = fourth_row.rotate_left(3, constraint_system).ok()?;

    let result = vec![
        first_row.get(0)?.clone(),
        rotated_second_row.get(0)?.clone(),
        rotated_third_row.get(0)?.clone(),
        rotated_fourth_row.get(0)?.clone(),
        first_row.get(1)?.clone(),
        rotated_second_row.get(1)?.clone(),
        rotated_third_row.get(1)?.clone(),
        rotated_fourth_row.get(1)?.clone(),
        first_row.get(2)?.clone(),
        rotated_second_row.get(2)?.clone(),
        rotated_third_row.get(2)?.clone(),
        rotated_fourth_row.get(2)?.clone(),
        first_row.get(3)?.clone(),
        rotated_second_row.get(3)?.clone(),
        rotated_third_row.get(3)?.clone(),
        rotated_fourth_row.get(3)?.clone(),
    ];

    Some(result)
}

pub fn mix_columns<F: PrimeField>(
    input: &[UInt8::<F>],
    constraint_system: ConstraintSystemRef<F>,
) -> Option<Vec<UInt8::<F>>> {
    let mut mixed_input = UInt8::<F>::constant_vec(&[0_u8; 16]);
    for (i, column) in input.chunks(4).enumerate() {
        let column_aux = [
            column.first()?.clone(),
            column.get(1)?.clone(),
            column.get(2)?.clone(),
            column.get(3)?.clone(),
        ];
        let column_ret = gmix_column(&column_aux, constraint_system.clone())?;

        *mixed_input.get_mut(i * 4)? = column_ret.first()?.clone();
        *mixed_input.get_mut(i * 4 + 1)? = column_ret.get(1)?.clone();
        *mixed_input.get_mut(i * 4 + 2)? = column_ret.get(2)?.clone();
        *mixed_input.get_mut(i * 4 + 3)? = column_ret.get(3)?.clone();
    }

    Some(mixed_input)
}

// TODO: this function should return a result.
fn gmix_column<F: PrimeField>(
    input: &[UInt8::<F>; 4],
    constraint_system: ConstraintSystemRef<F>,
) -> Option<[UInt8::<F>; 4]> {
    let mut b: Vec<UInt8::<F>> = Vec::new();

    for c in input.iter() {
        // TODO: Refactor this when and() is implemented for UInt8::<F>.
        let h_bits = c
            .shift_right(7, constraint_system.clone())
            .ok()?
            .to_bits_le()
            .ok()?
            .iter()
            .zip(UInt8::<F>::constant(1).to_bits_le().ok()?)
            .filter_map(|(a, b)| a.and(&b).ok())
            .collect::<Vec<Boolean<F>>>();
        let h = UInt8::<F>::from_bits_le(&h_bits);
        let partial_b_byte = c.shift_left(1, constraint_system.clone()).ok()?;
        let b_byte: UInt8<F> = partial_b_byte
            .xor(
                &helpers::multiply(&h, &UInt8::<F>::constant(0x1B), constraint_system.clone())
                    .ok()?,
            )
            .ok()?;

        b.push(b_byte);
    }

    Some([
        b.first()?
            .xor(input.get(3)?)
            .ok()?
            .xor(input.get(2)?)
            .ok()?
            .xor(b.get(1)?)
            .ok()?
            .xor(input.get(1)?)
            .ok()?,
        b.get(1)?
            .xor(input.first()?)
            .ok()?
            .xor(input.get(3)?)
            .ok()?
            .xor(b.get(2)?)
            .ok()?
            .xor(input.get(2)?)
            .ok()?,
        b.get(2)?
            .xor(input.get(1)?)
            .ok()?
            .xor(input.first()?)
            .ok()?
            .xor(b.get(3)?)
            .ok()?
            .xor(input.get(3)?)
            .ok()?,
        b.get(3)?
            .xor(input.get(2)?)
            .ok()?
            .xor(input.get(1)?)
            .ok()?
            .xor(b.first()?)
            .ok()?
            .xor(input.first()?)
            .ok()?,
    ])
}

// I'm doing it this way because if instead I did something like
// vec![...] there would be a huge stack allocation that, among other things,
// would make compilation (yes, compilation) incredibly slow.
#[allow(clippy::vec_init_then_push)]
pub fn lookup_table<F: PrimeField>(cs: ConstraintSystemRef<F>) -> Result<Vec<UInt8<F>>> {
    let mut ret = vec![];

    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x63)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x7C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x77)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x7B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF2)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x6B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x6F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC5)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x30)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x01)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x67)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x2B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xFE)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD7)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xAB)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x76)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xCA)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x82)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC9)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x7D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xFA)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x59)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x47)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF0)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xAD)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD4)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA2)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xAF)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x9C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA4)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x72)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC0)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB7)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xFD)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x93)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x26)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x36)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x3F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF7)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xCC)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x34)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA5)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE5)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF1)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x71)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD8)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x31)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x15)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x04)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC7)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x23)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC3)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x18)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x96)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x05)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x9A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x07)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x12)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x80)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE2)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xEB)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x27)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB2)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x75)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x09)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x83)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x2C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x1A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x1B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x6E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x5A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA0)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x52)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x3B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD6)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB3)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x29)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE3)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x2F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x84)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x53)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD1)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x00)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xED)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x20)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xFC)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB1)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x5B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x6A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xCB)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xBE)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x39)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x4A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x4C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x58)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xCF)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD0)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xEF)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xAA)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xFB)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x43)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x4D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x33)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x85)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x45)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF9)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x02)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x7F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x50)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x3C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x9F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA8)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x51)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA3)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x40)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x8F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x92)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x9D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x38)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF5)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xBC)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB6)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xDA)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x21)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x10)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xFF)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF3)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD2)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xCD)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x0C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x13)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xEC)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x5F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x97)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x44)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x17)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC4)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA7)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x7E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x3D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x64)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x5D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x19)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x73)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x60)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x81)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x4F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xDC)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x22)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x2A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x90)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x88)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x46)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xEE)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB8)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x14)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xDE)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x5E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x0B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xDB)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE0)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x32)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x3A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x0A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x49)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x06)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x24)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x5C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC2)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD3)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xAC)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x62)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x91)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x95)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE4)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x79)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE7)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC8)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x37)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x6D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x8D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD5)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x4E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA9)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x6C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x56)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF4)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xEA)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x65)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x7A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xAE)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x08)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xBA)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x78)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x25)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x2E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x1C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA6)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB4)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC6)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE8)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xDD)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x74)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x1F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x4B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xBD)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x8B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x8A)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x70)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x3E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB5)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x66)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x48)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x03)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF6)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x0E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x61)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x35)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x57)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB9)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x86)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xC1)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x1D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x9E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE1)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xF8)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x98)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x11)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x69)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xD9)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x8E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x94)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x9B)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x1E)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x87)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE9)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xCE)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x55)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x28)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xDF)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x8C)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xA1)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x89)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x0D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xBF)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xE6)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x42)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x68)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x41)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x99)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x2D)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x0F)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xB0)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0x54)?);
    ret.push(UInt8::<F>::new_constant(cs.clone(), 0xBB)?);
    ret.push(UInt8::<F>::new_constant(cs, 0x16)?);

    Ok(ret)
}

/* 
#[cfg(test)]
mod tests {
    use crate::aes_circuit;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar, uint8::UInt8};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_one_round_add_round_key_circuit() {
        let cs = ConstraintSystem::<F>::new_ref();
        let plaintext = UInt8::<F>::new_witness_vec(
            ark_relations::ns!(cs, "plaintext"),
            &[
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
                0x07, 0x34,
            ],
        )
        .unwrap();
        let secret_key = UInt8::<F>::new_witness_vec(
            ark_relations::ns!(cs, "secret_key"),
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
        )
        .unwrap();
        let expected_primitive_result = [
            0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
            0x48, 0x08,
        ];

        let after_add_round_key = aes_circuit::add_round_key(&plaintext, &secret_key).unwrap();

        assert_eq!(
            after_add_round_key.value().unwrap(),
            expected_primitive_result
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_one_round_column_mix_circuit() {
        let cs = ConstraintSystem::<F>::new_ref();
        let value_to_mix = UInt8::<F>::new_witness_vec(
            ark_relations::ns!(cs, "value_to_mix"),
            &[
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ],
        )
        .unwrap();
        let expected_primitive_mixed_value: [u8; 16] = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
            0x26, 0x4c,
        ];

        let mixed_column_vector = aes_circuit::mix_columns(&value_to_mix, cs.clone()).unwrap();

        assert_eq!(
            mixed_column_vector.value().unwrap(),
            expected_primitive_mixed_value
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_shift_rows() {
        let cs = ConstraintSystem::<F>::new_ref();
        // Generate random 16 bytes, and then check
        // that the AES shifting works like expected.
        let mut value_to_shift = vec![];
        for _i in 0_i32..16_i32 {
            value_to_shift
                .push(UInt8::<F>::new_witness(cs.clone(), || Ok(rand::random::<u8>())).unwrap());
        }

        let expected: Vec<&UInt8::<F>> = vec![
            value_to_shift.get(0).unwrap(),
            value_to_shift.get(5).unwrap(),
            value_to_shift.get(10).unwrap(),
            value_to_shift.get(15).unwrap(),
            value_to_shift.get(4).unwrap(),
            value_to_shift.get(9).unwrap(),
            value_to_shift.get(14).unwrap(),
            value_to_shift.get(3).unwrap(),
            value_to_shift.get(8).unwrap(),
            value_to_shift.get(13).unwrap(),
            value_to_shift.get(2).unwrap(),
            value_to_shift.get(7).unwrap(),
            value_to_shift.get(12).unwrap(),
            value_to_shift.get(1).unwrap(),
            value_to_shift.get(6).unwrap(),
            value_to_shift.get(11).unwrap(),
        ];

        let res = aes_circuit::shift_rows(&value_to_shift, cs.clone());
        for (index, byte) in res.unwrap().iter().enumerate() {
            assert_eq!(byte.value(), expected.get(index).unwrap().value());
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_one_round_sub_bytes_circuit() {
        let cs = ConstraintSystem::<F>::new_ref();
        let lookup_table = aes_circuit::lookup_table(cs.clone()).unwrap();
        let value_to_substitute = UInt8::<F>::new_witness_vec(
            ark_relations::ns!(cs, "value_to_mix"),
            &[
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
        )
        .unwrap();

        let expected_primitive_substituted_value: [u8; 16] = [
            0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
            0x52, 0x30,
        ];

        let substituted_value =
            aes_circuit::substitute_bytes(&value_to_substitute, &lookup_table).unwrap();

        assert_eq!(
            substituted_value.value().unwrap(),
            expected_primitive_substituted_value
        );
    }

    #[test]
    fn key_expansion_circuit() {
        let cs = ConstraintSystem::<F>::new_ref();
        let lookup_table = aes_circuit::lookup_table(cs.clone()).unwrap();
        let secret_key = UInt8::<F>::new_witness_vec(
            cs.clone(),
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
        )
        .unwrap();
        let result = aes_circuit::derive_keys(&secret_key, &lookup_table, cs).unwrap();

        assert_eq!(
            result.get(10).unwrap().value().unwrap(),
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6,
            ]
        );
    }
}
*/
