use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use anyhow::Result;
use digest::generic_array::GenericArray;
use poc_encryption_proof::{encrypt, synthesize_keys, verify_encryption};

fn main() -> Result<()> {
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];
    let primitive_secret_key = Aes128::new(GenericArray::from_slice(&secret_key));
    let (proving_key, verifying_key) = synthesize_keys()?;

    let (ciphertext, proof) = encrypt(&message, &secret_key, proving_key)?;
    let primitive_ciphertext = primitive_encrypt(&message, &primitive_secret_key);

    assert_eq!(primitive_ciphertext, ciphertext);
    assert!(verify_encryption(verifying_key, &proof)?);

    Ok(())
}

fn primitive_encrypt(message: &[u8; 16], primitive_secret_key: &Aes128) -> Vec<u8> {
    let mut encrypted_message = Vec::new();
    let mut block = GenericArray::clone_from_slice(message);
    primitive_secret_key.encrypt_block(&mut block);
    encrypted_message.extend_from_slice(block.as_slice());
    encrypted_message
}
