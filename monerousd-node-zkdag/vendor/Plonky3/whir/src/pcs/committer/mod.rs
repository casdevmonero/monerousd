use p3_matrix::extension::FlatMatrixView;
use p3_merkle_tree::MerkleTree;
use p3_sumcheck::commit::CodewordRows;

pub mod reader;
pub mod writer;

/// DB-371: every folded round's extension commitment opens from the lazy codeword ([`CodewordRows`]) too.
pub type ProverDataExt<F, EF, const N: usize, const DIGEST_ELEMS: usize> =
    MerkleTree<F, F, FlatMatrixView<F, EF, CodewordRows<F, EF>>, N, DIGEST_ELEMS>;

/// DB-371: the base commitment opens from the lazy codeword ([`CodewordRows`]), never a dense matrix.
pub type ProverData<F, const N: usize, const DIGEST_ELEMS: usize> =
    MerkleTree<F, F, CodewordRows<F>, N, DIGEST_ELEMS>;
