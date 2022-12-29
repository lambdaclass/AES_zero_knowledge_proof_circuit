/// Ark deps
use ark_crypto_primitives::encryption::constraints::AsymmetricEncryptionGadget;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsParameters, EdwardsProjective as JubJub, Fq,
};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{test_rng, UniformRand};
use simpleworks::gadgets::UInt8Gadget;
use ark_relations::{
    r1cs::{ConstraintSystem, ConstraintSystemRef},
};

/* The array 'a' is simply a copy of the input array 'r'
    * The array 'b' is each element of the array 'a' multiplied by 2
    * in Rijndael's Galois field
    * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */

/* arithmetic right shift, thus shifting in either zeros or ones */
/* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
/* Rijndael's Galois field */
fn gmix_column(input: &[UInt8Gadget; 4]) -> Option<[UInt8Gadget; 4]> {
    let mut b: [u8; 4] = [0; 4];

    for (i, c) in input.iter().enumerate() {
        let h = (c >> 7_usize) & 1;
        *b.get_mut(i)? = (c << 1_usize) ^ (h * 0x1B);
    }

    Some([
        b.first()? ^ input.get(3)? ^ input.get(2)? ^ b.get(1)? ^ input.get(1)?,
        b.get(1)? ^ input.first()? ^ input.get(3)? ^ b.get(2)? ^ input.get(2)?,
        b.get(2)? ^ input.get(1)? ^ input.first()? ^ b.get(3)? ^ input.get(3)?,
        b.get(3)? ^ input.get(2)? ^ input.get(1)? ^ b.first()? ^ input.first()?,
    ])
}
