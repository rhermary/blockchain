use blockchain::cryptography::sha::{SHA, hash};
fn main() {
    hash("The quick brown fox jumps over the lazy dog", SHA::SHA1);
}
