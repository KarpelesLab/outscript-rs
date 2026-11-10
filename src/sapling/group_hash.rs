//! `GroupHash^J` and `FindGroupHash^J` (protocol specification §5.4.9.5):
//! hashing to the prime-order subgroup of Jubjub.

use super::jubjub::Point;
use super::prf::blake2s_256;

/// The uniform random string `URS` every group hash starts with: the ASCII
/// hex of a hash chosen after the algorithm was fixed.
pub const URS: &[u8; 64] = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

/// `GroupHash^J(D, M)`: BLAKE2s-256 of `URS ‖ M` personalized with `D`,
/// decoded as a point and multiplied by the cofactor. `None` when the hash
/// is not a point, or lands on the identity.
pub fn group_hash(personalization: &[u8; 8], message: &[u8]) -> Option<Point> {
    group_hash_parts(personalization, message, &[])
}

fn group_hash_parts(personalization: &[u8; 8], message: &[u8], tail: &[u8]) -> Option<Point> {
    let hash = blake2s_256(personalization, &[URS, message, tail]);
    let p = Point::from_bytes(&hash)?.mul_by_cofactor();
    (!p.is_identity()).then_some(p)
}

/// `FindGroupHash^J(D, M)`: the first of `GroupHash(D, M ‖ [i])` for
/// `i = 0, 1, ...` that is a point. `None` if all 256 fail, which does not
/// happen in practice.
pub fn find_group_hash(personalization: &[u8; 8], message: &[u8]) -> Option<Point> {
    (0..=255u8).find_map(|i| group_hash_parts(personalization, message, &[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_land_in_the_prime_order_subgroup() {
        let p = find_group_hash(b"Zcash_G_", b"").unwrap();
        assert!(p.is_prime_order());
        // not every input hashes to a point
        let misses = (0..=255u8)
            .filter(|&i| group_hash(b"Zcash_gd", &[i]).is_none())
            .count();
        assert!(misses > 64 && misses < 192, "{misses}");
    }
}
