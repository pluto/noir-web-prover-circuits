use std::{cell::RefCell, path::Path, rc::Rc};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};

use clap::Parser;
use noir::NoirCircuit;
use simple::NoirProgram;

pub mod bridge;
pub mod noir;
pub mod simple;

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

    let mut cs = ConstraintSystem::<Fr>::new();
    cs.mode = SynthesisMode::Setup;
    cs.optimization_goal = OptimizationGoal::Constraints;
    let cs = ConstraintSystemRef::<Fr>::CS(Rc::new(RefCell::new(cs)));
    dbg!(cs.num_instance_variables());
    dbg!(cs.num_witness_variables());

    let program = NoirProgram::new(&noir_json);
    program.generate_constraints(cs.clone());
    cs.finalize();
    dbg!(cs.num_constraints());

    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });

    dbg!(cs.to_matrices());
    dbg!(cs.num_instance_variables());
    dbg!(cs.num_witness_variables());
    // TODO: Note the first instance assignment is for the CONSTANT terms, so it should usually just be 1
    cs.borrow_mut().unwrap().instance_assignment = vec![Fr::ONE, Fr::ONE];
    cs.borrow_mut().unwrap().witness_assignment = vec![Fr::ONE, -Fr::ONE];
    dbg!(cs.is_satisfied());
}
