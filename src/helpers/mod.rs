use crate::helpers::traits::ToAnyhow;
use anyhow::{anyhow, Result};
use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::Boolean, R1CSVar, ToBitsGadget, uint8::UInt8};
use ark_relations::r1cs::ConstraintSystemRef;
use log::debug;
use simpleworks::{
    gadgets::{traits::BitwiseOperationGadget},
};

pub mod traits;

pub fn add<F:PrimeField>(augend: &UInt8::<F>, addend: &UInt8::<F>) -> Result<UInt8::<F>> {
    let augend = augend.to_bits_be()?;
    let addend = addend.to_bits_be()?;
    let mut sum = vec![Boolean::<F>::FALSE; augend.len()];
    let mut carry = Boolean::<F>::FALSE;
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
    Ok(UInt8::<F>::from_bits_le(&sum))
}

pub fn multiply<F:PrimeField>(
    multiplicand: &UInt8::<F>,
    multiplier: &UInt8::<F>,
    constraint_system: ConstraintSystemRef<F>,
) -> Result<UInt8::<F>> {
    let mut product = UInt8::<F>::constant(0_u8);

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

pub fn debug_constraint_system_status<F:PrimeField>(
    message: &str,
    constraint_system: ConstraintSystemRef<F>,
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
