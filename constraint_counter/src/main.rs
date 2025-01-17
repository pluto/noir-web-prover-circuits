use std::{cell::RefCell, path::Path, rc::Rc};

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisMode};
use folding_schemes::{frontend::FCircuit, utils::PathOrBin};
use noir::NoirFCircuit;
use utils::VecFpVar;

pub mod bridge;
pub mod noir;
pub mod utils;

const NOIR_JSON: &[u8] = include_bytes!("../../target/bin.json");

pub fn main() {
    // dbg!(noir::num_constraints::<ark_bn254::Fr>(NOIR_JSON));
    let circuit = NoirFCircuit::<1, 1024>::new(NOIR_JSON).unwrap();

    // circuit.generate_constraints(vec![], VecFpVar::default());

    let mut cs = ConstraintSystem::<Fr>::new();
    cs.mode = SynthesisMode::Prove {
        construct_matrices: false,
    };
    let cs = dbg!(ConstraintSystemRef::<Fr>::CS(Rc::new(RefCell::new(cs))));

    // cs.set_mode(ark_relations::r1cs::SynthesisMode::Setup);

    // .set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);

    let pub_inputs = vec![Fr::ZERO];
    let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(pub_inputs.clone())).unwrap();

    let external_inputs = vec![Fr::ZERO; 1024];
    let external_inputs =
        Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(external_inputs)).unwrap();
    let start = std::time::Instant::now();
    circuit
        .generate_step_constraints(cs.clone(), z_i, VecFpVar(external_inputs))
        .unwrap();
    println!("Duration for witness solving: {:?}", start.elapsed());

    // cs.finalize();
    // let matrices = cs.to_matrices().unwrap();
    dbg!(cs.num_constraints());
}
