// extern crate sha2;
// use std::convert::TryInto;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use elgamal_ristretto::ciphertext::Ciphertext;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;
use rand_core::OsRng;

fn key_gen() -> (PublicKey, SecretKey) {
    let mut csprng = OsRng;
    let sk = SecretKey::new(&mut csprng);
    let pk = PublicKey::from(&sk);
    return (pk, sk);
}
fn encrypt(pk: PublicKey, message: RistrettoPoint) -> Ciphertext {
    return pk.encrypt(&message);
}
fn decrypt(sk: SecretKey, cphtxt: Ciphertext) -> RistrettoPoint {
    return sk.decrypt(&cphtxt);
}
fn bytes_to_point(bytes: &[u8; 32]) -> RistrettoPoint {
    let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(bytes);
    return p;
}
fn point_to_bytes(point: RistrettoPoint) -> [u8; 32] {
    return *point.compress().as_bytes();
}
fn decode(point: RistrettoPoint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(point.compress().as_bytes());
    bytes
}
fn encode(str: &[u8; 32]) -> RistrettoPoint {
    return CompressedRistretto::from_slice(str)
        .decompress()
        .unwrap();
}
#[cfg(test)]
mod test {
    // pk.encrypt(&p);
    // sk.prove_knowledge();
    fn message() -> [u8; 32] {
        let bytes = *b"11111111111111111111111111111111";
        return bytes;
    }
    use super::*;
    #[test]
    fn generate_pair() {
        let (_pk, _sk) = key_gen();
        // pk.encrypt(&msg);
    }
    #[test]
    fn to_string() {
        let msg: [u8; 32] = message();
        let point: RistrettoPoint = encode(&msg);
        let expected_bytes = decode(point);
        assert_eq!(msg, expected_bytes)
    }
    #[test]
    fn encryption() {
        let secret: RistrettoPoint = bytes_to_point(&message());
        let (pk, sk) = key_gen();
        let ciphertext = encrypt(pk, secret);
        assert_eq!(secret, decrypt(sk, ciphertext));
    }
}
