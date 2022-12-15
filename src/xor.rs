use ark_bls12_381::{Bls12_381, FqParameters};
use ark_ed_on_bls12_381::Fq;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
// use ark_marlin::Marlin;
use ark_marlin::{IndexVerifierKey, Marlin, Proof, SimpleHashFiatShamirRng};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint32::UInt32;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::rand::prelude::StdRng;
use blake2::Blake2s;
use rand_chacha::ChaChaRng;
type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fq>>;
type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
type MarlinInst = Marlin<Fq, MultiPC, FS>;
type MarlinProof = Proof<Fq, MultiPC>;
type IndexVK = IndexVerifierKey<Fq, MultiPC>;
use std::{cell::RefCell, rc::Rc};
pub fn xor_and_verify(x: u32, y: u32) -> (IndexVK, MarlinProof, u32) {
    let mut rng = simpleworks::marlin::generate_rand();
    let cs = ConstraintSystem::<Fq>::new_ref();
    let x_witness = UInt32::new_witness(ark_relations::ns!(cs, "x_witness"), || Ok(x)).unwrap();
    let y_witness = UInt32::new_witness(ark_relations::ns!(cs, "y_witness"), || Ok(y)).unwrap();
    let z = x_witness.xor(&y_witness).unwrap().value().unwrap();
    let srs = simpleworks::marlin::generate_universal_srs(&mut rng).unwrap();
    let cs_clone = (*cs
        .borrow()
        .ok_or("Error borrowing")
        .map_err(|e| anyhow::anyhow!("{}", e))
        .unwrap())
    .clone();
    let cs_clone_2 = (*cs
        .borrow()
        .ok_or("Error borrowing")
        .map_err(|e| anyhow::anyhow!("{}", e))
        .unwrap())
    .clone();
    let cs_ref_first_clone = ConstraintSystemRef::CS(Rc::new(RefCell::new(cs_clone)));
    let cs_ref_second_clone = ConstraintSystemRef::CS(Rc::new(RefCell::new(cs_clone_2)));
    let (index_pk, index_vk) =
        MarlinInst::index_from_constraint_system(&srs, cs_ref_first_clone).unwrap();
    let proof =
        MarlinInst::prove_from_constraint_system(&index_pk, cs_ref_second_clone, &mut rng).unwrap();
    (index_vk, proof, z)
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn xor() -> () {
        let mut rng = ark_std::test_rng();
        let x = 1;
        let y = 2;
        let z = x ^ y;
        let (index_vk, proof, xor_result) = xor_and_verify(x, y);
        assert_eq!(xor_result, z);
        assert!(MarlinInst::verify(&index_vk, &[], &proof, &mut rng).unwrap());
    }
}
