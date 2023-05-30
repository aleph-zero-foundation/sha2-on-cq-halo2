use halo2curves::pairing::MultiMillerLoop;

pub struct StaticTable<E: MultiMillerLoop> {
    x: E::Scalar,
}

impl<E: MultiMillerLoop> StaticTable<E> {
    pub fn commit(&self, srs_g2: &[E::G2Affine]) -> StaticCommittedTable<E> {
        StaticCommittedTable {
            x: (srs_g2[1] * self.x).into(),
        }
    }
}

pub struct StaticCommittedTable<E: MultiMillerLoop> {
    x: E::G2Affine,
}
