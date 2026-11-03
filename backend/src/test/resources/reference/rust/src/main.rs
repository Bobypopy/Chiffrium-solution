use sha2::{Digest, Sha256};

fn hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
