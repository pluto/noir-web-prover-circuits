use std::{cell::RefCell, path::Path, rc::Rc};

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisMode};
use folding_schemes::{frontend::FCircuit, utils::PathOrBin};
use noir::NoirFCircuit;
use utils::{VecF, VecFpVar};

pub mod bridge;
pub mod noir;
pub mod utils;

const NOIR_JSON: &[u8] = include_bytes!("../../target/bin.json");
const PUBLIC_IO_LENGTH: usize = 1;
const PRIVATE_INPUT_LENGTH: usize = 1024;

pub fn main() {
    let circuit = NoirFCircuit::<PUBLIC_IO_LENGTH, PRIVATE_INPUT_LENGTH>::new(NOIR_JSON).unwrap();

    let mut cs = ConstraintSystem::<Fr>::new();
    cs.mode = SynthesisMode::Prove {
        construct_matrices: false,
    };
    let cs = dbg!(ConstraintSystemRef::<Fr>::CS(Rc::new(RefCell::new(cs))));

    // For public inputs, create a VecF with array of length PUBLIC_IO_LENGTH
    let pub_inputs = VecF([Fr::ZERO; PUBLIC_IO_LENGTH]);
    let z_i = VecFpVar::<Fr, PUBLIC_IO_LENGTH>::new_witness(cs.clone(), || Ok(pub_inputs)).unwrap();

    // For external inputs, create a VecF with array of length PRIVATE_INPUT_LENGTH
    let external_inputs = VecF([Fr::ZERO; PRIVATE_INPUT_LENGTH]);
    let external_inputs =
        VecFpVar::<Fr, PRIVATE_INPUT_LENGTH>::new_witness(cs.clone(), || Ok(external_inputs))
            .unwrap();

    let start = std::time::Instant::now();
    circuit
        .generate_step_constraints(cs.clone(), z_i, external_inputs)
        .unwrap();
    println!("Duration for witness solving: {:?}", start.elapsed());

    dbg!(cs.num_constraints());
}
