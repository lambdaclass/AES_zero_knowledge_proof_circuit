use ark_bls12_381::FqParameters;
use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint32::UInt32;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
pub struct XorCircuit {
    pub x: u32,
    pub y: u32,
}
impl ConstraintSynthesizer<ark_ed_on_bls12_381::Fq> for XorCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ark_ed_on_bls12_381::Fq>,
    ) -> Result<(), SynthesisError> {
        let x = UInt32::new_witness(ark_relations::ns!(cs, "a"), || Ok(self.x))?;
        let y = UInt32::new_witness(ark_relations::ns!(cs, "b"), || Ok(self.y))?;
        assert!(cs.is_satisfied().unwrap());
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn xor() -> () {
        let x: u32 = 1;
        let y: u32 = 2;
        let z: u32 = x ^ y;
        let cs = ConstraintSystem::<Fq>::new_ref();
        let x_witness = UInt32::new_witness(ark_relations::ns!(cs, "x_witness"), || Ok(x)).unwrap();
        let y_witness = UInt32::new_witness(ark_relations::ns!(cs, "y_witness"), || Ok(y)).unwrap();
        let z_from_gadget = x_witness.xor(&y_witness).unwrap();
        assert!(z_from_gadget.value().unwrap() == z);
    }
}
