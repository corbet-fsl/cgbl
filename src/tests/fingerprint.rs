use super::*;
#[test]
fn independent_hmac_vector_and_domain_separation() {
    let mut seed = [9; 32];
    let key = FingerprintKey::from_bytes(&mut seed);
    assert_eq!(seed, [0; 32]);
    let fingerprint = key.fingerprint("global", "development", b"synthetic-a");
    assert_eq!(
        fingerprint,
        "727c49b7a4dfdd6e5f8e70e1ca4473b3d1077954f59cfed7873ab8c3e4cf69f3"
    );
    assert_ne!(
        fingerprint,
        key.fingerprint("other", "development", b"synthetic-a")
    );
    assert_ne!(
        fingerprint,
        key.fingerprint("global", "other", b"synthetic-a")
    );
    assert_ne!(
        key.fingerprint("a", "bc", b"d"),
        key.fingerprint("ab", "c", b"d")
    );
    assert_ne!(
        fingerprint,
        FingerprintKey::from_bytes(&mut [8; 32]).fingerprint(
            "global",
            "development",
            b"synthetic-a"
        )
    );
}
