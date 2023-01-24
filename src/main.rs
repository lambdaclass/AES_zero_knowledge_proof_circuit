use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use anyhow::Result;
use ark_bls12_377::Fr;
use digest::generic_array::GenericArray;
use poc_encryption_proof::encrypt_cs;

fn main() -> Result<()> {
    env_logger::init();
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];

    let primitive_secret_key = Aes128::new(GenericArray::from_slice(&secret_key));

    let primitive_ciphertext = primitive_encrypt(&message, &primitive_secret_key);

    let cs = encrypt_cs::<Fr>(&message,&secret_key,&primitive_ciphertext).unwrap();

    println!("CS");
    println!("Satisfied: {:?}", cs.is_satisfied());
    println!("Constraints: {}", cs.num_constraints());
    println!("Instance variables: {}", cs.num_instance_variables());
    println!("Witness variables: {}", cs.num_witness_variables());;

    /* 
    let primitive_secret_key = Aes128::new(GenericArray::from_slice(&secret_key));
    let (proving_key, verifying_key) = synthesize_keys(message.len())?;

    let primitive_ciphertext = primitive_encrypt(&message, &primitive_secret_key);
    let proof = encrypt(&message, &secret_key, &primitive_ciphertext, proving_key)?;

    assert!(verify_encryption(
        verifying_key,
        &proof,
        &primitive_ciphertext
    )?);
*/
    Ok(())
}

pub fn primitive_encrypt(message: &[u8; 16], primitive_secret_key: &Aes128) -> Vec<u8> {
    let mut encrypted_message = Vec::new();
    let mut block = GenericArray::clone_from_slice(message);
    primitive_secret_key.encrypt_block(&mut block);
    encrypted_message.extend_from_slice(block.as_slice());
    encrypted_message
}
