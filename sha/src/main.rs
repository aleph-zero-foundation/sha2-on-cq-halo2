use crate::simple_circuit::SimpleCircuit;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::plonk::Circuit;
use plotters::prelude::*;
use crate::circuit::ShaCircuit;

mod circuit;
mod simple_circuit;
mod tables;

fn draw_circuit<E: MultiMillerLoop, C: Circuit<E>>(c: &C, k: u32, filename: &str) {
    let filename = format!("{filename}.png");
    let root = BitMapBackend::new(&filename, (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Circuit Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_labels(true)
        .show_equality_constraints(true)
        .render(k, c, &root)
        .unwrap();
}

fn main() {
    draw_circuit(&SimpleCircuit::<Bn256>::default(), 4, "simple_circuit");
    draw_circuit(&ShaCircuit::<Bn256>::default(), 5, "sha_circuit");
}
