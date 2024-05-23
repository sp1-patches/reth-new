//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

// use zkevm_lib::SP1Input;

/// The main entrypoint for the zkVM program.
pub fn main() {
    // let sp1_input = sp1_zkvm::io::read::<SP1Input>();
    // sp1_input.verify_stf().expect("Failed to verify STF");
}
