use halo2_proofs::halo2curves::bn256::Bn256;
use plotters::prelude::*;
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::Circuit;
use crate::simple_circuit::SimpleCircuit;

mod simple_circuit;
mod tables;
mod circuit;

fn draw_circuit<E: MultiMillerLoop, C: Circuit<E>>(c: &C, k: u32) {
    let root = BitMapBackend::new("simple_circuit.png", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Simple Circuit Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_labels(true)
        .show_equality_constraints(true)
        .render(k, c, &root)
        .unwrap();
}

fn main() {
    draw_circuit(&SimpleCircuit::<Bn256>::default(), 4);
}
