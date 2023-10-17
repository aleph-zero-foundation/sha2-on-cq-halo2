use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Bn256;
use plotters::prelude::*;
use crate::simple_circuit::SimpleCircuit;

mod simple_circuit;

fn main() {
    let circuit: SimpleCircuit<Bn256> = SimpleCircuit {
        a: Value::known(1.into()),
        b: Value::known(2.into()),
        _marker: Default::default(),
    };

    let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Simple Circuit Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_labels(true)
        .mark_equality_cells(true)
        .show_equality_constraints(true)
        .render(5, &circuit, &root)
        .unwrap();



    // Generate the DOT graph string.
    let dot_string = halo2_proofs::dev::circuit_dot_graph(&circuit);
    print!("{}", dot_string);
}
