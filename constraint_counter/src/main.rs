use std::{cell::RefCell, path::Path, rc::Rc};

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};

use clap::Parser;

use noir::NoirProgram;

pub mod noir;

#[derive(Parser)]
#[command(name = "constraint_counter")]
#[command(about = "Count constraints in Noir circuits")]
struct Args {
    /// Path to the circuit JSON file
    #[arg(short, long)]
    circuit: String,
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
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_mock_noir_solve() {
        // Circuit definition:
        // x_0 * w_0 + w_1 + 2 == 0
        let json_path = Path::new("./mock").join(format!("mock.json"));
        let noir_json = std::fs::read(&json_path).unwrap();

        let program = NoirProgram::new(&noir_json);
        // NOTE: Don't need to have the instance assignment set to 1 here, so we need a method to handle this if we were sticking with this CS.
        program.solve(&[Fr::from(2)], &[Fr::from(3), -Fr::from(8)]);
    }
}
