use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint32::UInt32;
use ark_relations::r1cs::ConstraintSystemRef;

pub fn xor(x: u32, y: u32, cs: &ConstraintSystemRef<Fq>) -> u32 {
    let x_witness = UInt32::new_witness(ark_relations::ns!(cs, "x_xor_witness"), || Ok(x)).unwrap();
    let y_witness = UInt32::new_witness(ark_relations::ns!(cs, "y_xor_witness"), || Ok(y)).unwrap();
    let z = x_witness.xor(&y_witness).unwrap().value().unwrap();
    z
}

pub fn add(x: u32, y: u32, cs: &ConstraintSystemRef<Fq>) -> u32 {
    let x_witness = UInt32::new_witness(ark_relations::ns!(cs, "x_add_witness"), || Ok(x)).unwrap();
    let y_witness = UInt32::new_witness(ark_relations::ns!(cs, "y_add_witness"), || Ok(y)).unwrap();
    let z = UInt32::addmany(&[x_witness, y_witness])
        .unwrap()
        .value()
        .unwrap();
    z
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::*;
    use ark_std::rand::{Rng, SeedableRng};
    use ark_relations::r1cs::ConstraintSystem;

    // Generate 2 random integers and try
    // to calculate a xor inside a Constraint System.
    #[test]
    fn test_xor_and_verify_result() -> () {
        let seed = [
            1, 0, 52, 0,
            0, 0, 0, 0,
            1, 0, 10, 0,
            22, 32, 0, 0,
            2, 0, 55, 49,
            0, 11, 0, 0,
            3, 0, 0, 0,
            0, 0, 2, 92,
        ];
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let x: u32 = rng.gen_range(0..=u32::MAX);
        let y: u32 = rng.gen_range(0..=u32::MAX);
        let expected: u32 = x ^ y;
        let cs = ConstraintSystem::<Fq>::new_ref();
        let z = xor(x, y, &cs);
        assert_eq!(expected, z);
        // This one takes a while
        let (index_vk, proof) = prover::prove(cs);
        assert!(prover::MarlinInst::verify(&index_vk, &[], &proof, &mut rng).unwrap());
    }

    #[test]
    fn test_add_and_verify_result() -> () {
        let seed = [
            1, 0, 52, 0,
            0, 0, 0, 0,
            1, 0, 10, 0,
            22, 32, 0, 0,
            2, 0, 55, 49,
            0, 11, 0, 0,
            3, 0, 0, 0,
            0, 0, 2, 92,
        ];
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let x: u32 = rng.gen_range(0..=u32::MAX);
        let y: u32 = rng.gen_range(0..=u32::MAX);
        let expected: u32 = x + y;
        let cs = ConstraintSystem::<Fq>::new_ref();
        let z = add(x, y, &cs);
        assert_eq!(expected, z);
        // This one takes a while
        let (index_vk, proof) = prover::prove(cs);
        assert!(prover::MarlinInst::verify(&index_vk, &[], &proof, &mut rng).unwrap());
    }
}
