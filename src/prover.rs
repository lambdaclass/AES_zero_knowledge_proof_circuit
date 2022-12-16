use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::Fq;
use ark_marlin::{IndexVerifierKey, Marlin, Proof, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use blake2::Blake2s;
use rand_chacha::ChaChaRng;
pub type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fq>>;
pub type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
pub type MarlinInst = Marlin<Fq, MultiPC, FS>;
pub type MarlinProof = Proof<Fq, MultiPC>;
pub type IndexVK = IndexVerifierKey<Fq, MultiPC>;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use std::{cell::RefCell, rc::Rc};
pub fn prove(cs: ConstraintSystemRef<Fq>) -> (IndexVK, MarlinProof) {
    let mut rng = simpleworks::marlin::generate_rand();
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
    (index_vk, proof)
}
