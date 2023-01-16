use crate::helpers::traits::ToAnyhow;
use anyhow::{anyhow, Result};
use ark_r1cs_std::{prelude::Boolean, R1CSVar, ToBitsGadget};
use log::debug;
use simpleworks::{
    gadgets::{traits::BitShiftGadget, ConstraintF, UInt8Gadget},
    marlin::ConstraintSystemRef,
};

pub mod traits;

pub fn add(augend: &UInt8Gadget, addend: &UInt8Gadget) -> Result<UInt8Gadget> {
    let augend = augend.to_bits_be()?;
    let addend = addend.to_bits_be()?;
    let mut sum = vec![Boolean::<ConstraintF>::FALSE; augend.len()];
    let mut carry = Boolean::<ConstraintF>::FALSE;
    for (i, (augend_bit, addend_bit)) in augend.iter().zip(addend).enumerate().rev() {
        // Bit by bit sum is an xor for the augend, the addend and the carry bits.
        // carry in | addend | augend | carry out | augend + addend |
        //     0    |    0   |   0    |     0     |        0        |
        //     0    |    0   |   1    |     0     |        1        |
        //     0    |    1   |   0    |     0     |        1        |
        //     0    |    1   |   1    |     1     |        0        |
        //     1    |    0   |   0    |     0     |        1        |
        //     1    |    0   |   1    |     1     |        0        |
        //     1    |    1   |   0    |     1     |        0        |
        //     1    |    1   |   1    |     1     |        1        |
        // sum[i] = (!carry & (augend_bit ^ addend_bit)) | (carry & !(augend_bit ^ addend_bit))
        //        = augend_bit ^ addend_bit ^ carry
        *sum.get_mut(i)
            .ok_or_else(|| anyhow!("Error accessing the index of sum"))? =
            carry.xor(augend_bit)?.xor(&addend_bit)?;
        // To simplify things, the variable carry acts for both the carry in and
        // the carry out.
        // The carry out is augend & addend when the carry in is 0, and it is
        // augend | addend when the carry in is 1.
        // carry = carry.not()
        carry = (carry.not().and(&(augend_bit.and(&addend_bit)?))?)
            .or(&(carry.and(&(augend_bit.or(&addend_bit)?))?))?;
    }
    sum.reverse();
    Ok(UInt8Gadget::from_bits_le(&sum))
}

pub fn multiply(
    multiplicand: &UInt8Gadget,
    multiplier: &UInt8Gadget,
    constraint_system: ConstraintSystemRef,
) -> Result<UInt8Gadget> {
    let mut product = UInt8Gadget::constant(0_u8);

    for (i, multiplier_bit) in multiplier.to_bits_be()?.iter().rev().enumerate() {
        // If the divisor bit is a 1.
        if multiplier_bit.value()? {
            let addend = if i != 0 {
                multiplicand.shift_left(i, constraint_system.clone())?
            } else {
                multiplicand.clone()
            };
            product = add(&product, &addend)?;
        }
    }

    Ok(product)
}

pub fn debug_constraint_system_status(
    message: &str,
    constraint_system: ConstraintSystemRef,
) -> Result<()> {
    let matrix = constraint_system
        .to_matrices()
        .to_anyhow("Error converting the constraint system to matrices")?;
    debug!("CONSTRAINT SYSTEM STATUS: {message}");
    debug!("Number of constraints: {}", matrix.num_constraints);
    debug!("Number of variables: {}", matrix.num_instance_variables);
    debug!("Number of witnesses: {}", matrix.num_witness_variables);
    debug!(
        "Number of non-zero: {}",
        matrix.a_num_non_zero + matrix.b_num_non_zero + matrix.c_num_non_zero
    );
    Ok(())
}

pub fn sample_message(amount_of_bytes: usize) -> Vec<u8> {
    let mut message = vec![0_u8; amount_of_bytes];

    let mut _random_message: [u8; 16] = rand::random();
    for (raw_message_byte, random_message_byte) in message.iter_mut().zip(_random_message) {
        *raw_message_byte = random_message_byte;
        _random_message = rand::random();
    }

    message
}

// TODO: Support non-multiple of 16 bytes messages.
pub fn primitive_encrypt(message: &[u8], key: &[u8]) -> Vec<u8> {
    let primitive_secret_key = <aes::Aes128 as aes::cipher::KeyInit>::new(
        digest::generic_array::GenericArray::from_slice(key),
    );
    let mut encrypted_message: Vec<u8> = Vec::new();

    message.chunks_exact(16).for_each(|chunk| {
        let mut block = digest::generic_array::GenericArray::clone_from_slice(chunk);
        aes::cipher::BlockEncrypt::encrypt_block(&primitive_secret_key, &mut block);
        encrypted_message.extend_from_slice(&block);
    });

    encrypted_message
}
