use blockchain::cryptography::sha::compute;

#[test]
fn compute_test() {
    assert_eq!(3, compute());
}