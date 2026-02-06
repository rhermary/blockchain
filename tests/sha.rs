use blockchain::cryptography::sha::{SHA, hash};

#[test]
fn compute_test() {
    hash("The quick brown fox jumps over the lazy dog", SHA::SHA1);
    hash("", SHA::SHA1);
}
//assert 160 bits for SHA1
// Validation? https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing``