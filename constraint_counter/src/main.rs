use std::{cell::RefCell, path::Path, rc::Rc};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};

use clap::Parser;
// use noir::NoirCircuit;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_noir_circuit() {
        // Circuit definition:
        // x_0 * w_0 + w_1 + 2 == 0
        let json_path = Path::new("./mock").join(format!("mock.json"));
        let noir_json = std::fs::read(&json_path).unwrap();

        let mut cs = ConstraintSystem::<Fr>::new();
        cs.mode = SynthesisMode::Setup;
        cs.optimization_goal = OptimizationGoal::Constraints;
        let cs = ConstraintSystemRef::<Fr>::CS(Rc::new(RefCell::new(cs)));

        let program = NoirProgram::new(&noir_json);
        program.generate_constraints(cs.clone());
        cs.finalize();

        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });

        dbg!(cs.to_matrices());
        dbg!(cs.num_instance_variables());
        dbg!(cs.num_witness_variables());
        // NOTE, the 0th instance assignment is the constant term enabler.
        // This example is:
        // 2 * 3 + (-8) + 2 == 0
        cs.borrow_mut().unwrap().instance_assignment = vec![Fr::ONE, Fr::from(2)];
        cs.borrow_mut().unwrap().witness_assignment = vec![Fr::from(3), -Fr::from(8)];
        cs.is_satisfied();
    }
}
