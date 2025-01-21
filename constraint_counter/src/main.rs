use std::{cell::RefCell, path::Path, rc::Rc};

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisMode};

use clap::Parser;
use noir::NoirFCircuit;

pub mod bridge;
pub mod noir;

#[derive(Parser)]
#[command(name = "constraint_counter")]
#[command(about = "Count constraints in Noir circuits")]
struct Args {
    /// Path to the circuit JSON file
    #[arg(short, long)]
    circuit: String,

    /// Length of public IO
    #[arg(long)]
    public_io_length: usize,

    /// Length of private input
    #[arg(long)]
    private_input_length: usize,
}

pub fn main() {
    let args = Args::parse();

    let json_path = Path::new("./target").join(format!("{}.json", args.circuit));
    let noir_json = match std::fs::read(&json_path) {
        Ok(contents) => contents,
        Err(e) => {
            eprintln!("Error reading file {}: {}", json_path.display(), e);
            std::process::exit(1);
        }
    };

    let circuit = NoirFCircuit::new(&noir_json);

    let mut cs = ConstraintSystem::<Fr>::new();
    cs.mode = SynthesisMode::Prove {
        construct_matrices: false,
    };
    let cs = ConstraintSystemRef::<Fr>::CS(Rc::new(RefCell::new(cs)));

    // Use array directly for public inputs
    let pub_inputs = vec![Fr::ZERO; args.public_io_length];
    let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(pub_inputs)).unwrap();

    // Use array directly for external inputs
    let external_inputs = vec![Fr::ZERO; args.private_input_length];
    let external_inputs =
        Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(external_inputs)).unwrap();

    let start = std::time::Instant::now();
    circuit
        .generate_step_constraints(cs.clone(), &z_i, &external_inputs)
        .unwrap();
    println!("Duration for witness solving: {:?}", start.elapsed());

    dbg!(cs.num_constraints());
}
