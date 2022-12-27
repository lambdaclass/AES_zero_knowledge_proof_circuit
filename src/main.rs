use anyhow::Result;
use poc_encryption_proof::{encrypt, synthetize_keys, verify_encryption};

fn main() -> Result<()> {
    let message = vec![1u8, 2u8, 3u8, 10u8, 9u8, 7u8];
    let secret_key = vec![1u8, 1u8, 1u8, 1u8];
    let (proving_key, verifying_key) = synthetize_keys()?;

    let (_ciphertext, proof) = encrypt(message, secret_key, proving_key)?;

    assert!(verify_encryption(verifying_key, &proof)?);

    Ok(())
}
