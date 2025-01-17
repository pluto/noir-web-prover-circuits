use std::path::Path;

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::{frontend::FCircuit, utils::PathOrBin};
use noir::NoirFCircuit;
use utils::VecFpVar;

pub mod bridge;
pub mod noir;
pub mod utils;

const NOIR_JSON: &[u8] = include_bytes!("../../target/bin.json");

pub fn main() {
    // dbg!(noir::num_constraints::<ark_bn254::Fr>(NOIR_JSON));
    let circuit = NoirFCircuit::<Fr, 1024>::new((PathOrBin::Bin(NOIR_JSON.to_vec()), 1)).unwrap();

    // circuit.generate_constraints(vec![], VecFpVar::default());

    let cs = ConstraintSystem::<Fr>::new_ref();

    let pub_inputs = vec![Fr::ZERO];
    let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(pub_inputs.clone())).unwrap();

    let external_inputs = vec![Fr::ZERO; 1024];
    let external_inputs =
        Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(external_inputs)).unwrap();
    circuit
        .generate_step_constraints(cs.clone(), 0, z_i, VecFpVar(external_inputs))
        .unwrap();

    dbg!(cs.num_constraints());
}
