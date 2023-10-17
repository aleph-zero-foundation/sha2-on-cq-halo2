use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Bn256;
use plotters::prelude::*;
use crate::simple_circuit::SimpleCircuit;

mod simple_circuit;

fn main() {
    let circuit: SimpleCircuit<Bn256> = SimpleCircuit {
        a: Value::unknown(),
        b: Value::unknown(),
        _marker: Default::default(),
    };

    let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Simple Circuit Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_labels(true)
        .show_equality_constraints(true)
        .render(4, &circuit, &root)
        .unwrap();
}
