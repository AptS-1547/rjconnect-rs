use md5_digest::{Digest, Md5};

pub const MD5_CHALLENGE_LENGTH: usize = 16;
pub const MD5_CHALLENGE_LENGTH_WIRE: u8 = 16;

pub fn calculate(identifier: u8, password: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update([identifier]);
    hasher.update(password);
    hasher.update(challenge);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_md5_vector() {
        let challenge = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        assert_eq!(
            calculate(7, b"secret", &challenge),
            [
                0x82, 0x16, 0x43, 0x66, 0x5b, 0x43, 0x03, 0x59, 0xe5, 0x2a, 0xc5, 0x24, 0xd2, 0x9c,
                0x8f, 0x95,
            ]
        );
    }
}
