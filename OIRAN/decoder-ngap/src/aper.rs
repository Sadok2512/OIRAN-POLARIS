//! Bit-accurate ALIGNED PER reader (ITU-T X.691 Clause 10) scoped to the subset
//! required by TS 38.413 PDUSessionResourceSetup{Request,Response}Transfer and
//! their nested types. Ground truth for fixture generation is the `asn1tools`
//! Python library (codec `per`) running on the matching ASN.1 subset.
//!
//! Rules implemented (aligned variant):
//! * Constrained INTEGER (lb..ub), range R = ub - lb + 1:
//!   - R <= 1: zero bits.
//!   - R <= 255: unaligned bit-field of ceil(log2(R)) bits (10.5.7.4 case b).
//!   - R <= 65536: octet-aligned, 1 or 2 octets (10.5.7.4 case c).
//!   - R > 65536: unsupported here (would require a length determinant).
//! * Extensible INTEGER / ENUMERATED / CHOICE: 1 extension bit, followed by
//!   the constrained encoding if ext=0, otherwise reported as unsupported.
//! * SEQUENCE: 1 extension bit (if extensible) + 1 bit per OPTIONAL field.
//! * SEQUENCE OF SIZE(lb..ub): size encoded as a constrained whole number
//!   with offset-from-lb, no alignment of items beyond the primitive rules.
//! * BIT STRING / OCTET STRING: length (constrained whole number) then
//!   octet-aligned content.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AperError {
    Truncated,
    Unsupported(String),
    OutOfRange(String),
}

pub struct AperReader<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> AperReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    pub fn position(&self) -> usize {
        self.bit
    }

    pub fn remaining_bits(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.bit)
    }

    pub fn read_bit(&mut self) -> Result<bool, AperError> {
        if self.bit >= self.data.len() * 8 {
            return Err(AperError::Truncated);
        }
        let v = (self.data[self.bit / 8] >> (7 - self.bit % 8)) & 1;
        self.bit += 1;
        Ok(v != 0)
    }

    pub fn read_bits(&mut self, n: usize) -> Result<u64, AperError> {
        if n > 64 || self.bit + n > self.data.len() * 8 {
            return Err(AperError::Truncated);
        }
        let mut value = 0u64;
        for _ in 0..n {
            value = (value << 1) | u64::from((self.data[self.bit / 8] >> (7 - self.bit % 8)) & 1);
            self.bit += 1;
        }
        Ok(value)
    }

    pub fn align(&mut self) {
        self.bit = (self.bit + 7) & !7;
    }

    pub fn read_octet(&mut self) -> Result<u8, AperError> {
        self.align();
        if self.bit + 8 > self.data.len() * 8 {
            return Err(AperError::Truncated);
        }
        let v = self.data[self.bit / 8];
        self.bit += 8;
        Ok(v)
    }

    pub fn read_octets(&mut self, n: usize) -> Result<&'a [u8], AperError> {
        self.align();
        let start = self.bit / 8;
        let end = start + n;
        if end > self.data.len() {
            return Err(AperError::Truncated);
        }
        self.bit = end * 8;
        Ok(&self.data[start..end])
    }

    /// Constrained whole number encoded as offset-from-zero. The caller supplies
    /// the range R = ub - lb + 1.
    pub fn read_constrained_whole(&mut self, range: u64) -> Result<u64, AperError> {
        if range <= 1 {
            return Ok(0);
        }
        if range <= 255 {
            // 10.5.7.4 case b: unaligned bit-field, minimum number of bits.
            let bits = (u64::BITS - (range - 1).leading_zeros()) as usize;
            self.read_bits(bits)
        } else if range <= 65536 {
            // 10.5.7.4 case c: octet-aligned, 1 or 2 octets.
            let octets = if range <= 256 { 1 } else { 2 };
            self.align();
            let mut v = 0u64;
            for _ in 0..octets {
                v = (v << 8) | u64::from(self.read_octet()?);
            }
            Ok(v)
        } else {
            Err(AperError::Unsupported(format!(
                "constrained whole number with range {range} > 65536 not supported"
            )))
        }
    }

    /// Semi-constrained length determinant used by OCTET/BIT STRING without a
    /// SIZE constraint. The determinant is 1 or 2 aligned octets.
    pub fn read_length_determinant(&mut self) -> Result<usize, AperError> {
        self.align();
        let first = self.read_octet()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        if first & 0xc0 == 0x80 {
            let second = self.read_octet()?;
            return Ok((((first & 0x3f) as usize) << 8) | second as usize);
        }
        Err(AperError::Unsupported(
            "fragmented length determinant not supported".into(),
        ))
    }

    /// Constrained INTEGER (lb..ub) without extensibility.
    pub fn read_constrained_integer(&mut self, lb: i64, ub: i64) -> Result<i64, AperError> {
        let range = (ub - lb + 1) as u64;
        let offset = self.read_constrained_whole(range)?;
        Ok(lb + offset as i64)
    }

    /// Constrained INTEGER (lb..ub, ...) with an extension marker. Returns the
    /// in-range value when ext=0; returns `AperError::Unsupported` when ext=1
    /// so callers can log the specific field name instead of silently dropping.
    pub fn read_extensible_integer(&mut self, lb: i64, ub: i64) -> Result<i64, AperError> {
        if self.read_bit()? {
            return Err(AperError::Unsupported(
                "integer value in extension addition not supported".into(),
            ));
        }
        self.read_constrained_integer(lb, ub)
    }

    /// Read a fixed-size OCTET STRING of `n` octets, octet-aligned.
    pub fn read_fixed_octet_string(&mut self, n: usize) -> Result<&'a [u8], AperError> {
        self.read_octets(n)
    }

    /// Read a BIT STRING with the given explicit bit-length. Content starts on
    /// the next octet boundary. Returns the raw bytes (last-byte low bits may
    /// be padding).
    pub fn read_bit_string_content(&mut self, bit_length: usize) -> Result<Vec<u8>, AperError> {
        self.align();
        let octets = bit_length.div_ceil(8);
        Ok(self.read_octets(octets)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bits_in_msb_first_order() {
        let mut r = AperReader::new(&[0b1010_0110]);
        assert!(r.read_bit().unwrap());
        assert!(!r.read_bit().unwrap());
        assert!(r.read_bit().unwrap());
        assert!(!r.read_bit().unwrap());
        assert_eq!(r.read_bits(4).unwrap(), 0b0110);
    }

    #[test]
    fn align_moves_to_next_octet_boundary() {
        let mut r = AperReader::new(&[0b1111_0000, 0xab]);
        let _ = r.read_bits(3).unwrap();
        assert_eq!(r.position(), 3);
        r.align();
        assert_eq!(r.position(), 8);
        assert_eq!(r.read_octet().unwrap(), 0xab);
    }

    #[test]
    fn constrained_whole_number_small_range_is_unaligned_bit_field() {
        // range=64 → ceil(log2(64))=6 bits unaligned.
        let data = [0b000001_11, 0b0000_0000];
        let mut r = AperReader::new(&data);
        assert_eq!(r.read_constrained_whole(64).unwrap(), 1);
        assert_eq!(r.position(), 6);
    }

    #[test]
    fn constrained_whole_number_medium_range_is_octet_aligned() {
        // range=256 → 1 octet aligned.
        let data = [0b0000_0000, 0x7f];
        let mut r = AperReader::new(&data);
        let _ = r.read_bit().unwrap();
        assert_eq!(r.read_constrained_whole(256).unwrap(), 0x7f);
        assert_eq!(r.position(), 16);
    }

    #[test]
    fn constrained_whole_number_large_range_is_two_octets() {
        let data = [0x00, 0x12, 0x34];
        let mut r = AperReader::new(&data);
        let _ = r.read_bit().unwrap();
        assert_eq!(r.read_constrained_whole(65536).unwrap(), 0x1234);
    }

    #[test]
    fn length_determinant_single_octet() {
        let mut r = AperReader::new(&[0x05]);
        assert_eq!(r.read_length_determinant().unwrap(), 5);
    }

    #[test]
    fn length_determinant_two_octet() {
        let mut r = AperReader::new(&[0x81, 0x00]);
        assert_eq!(r.read_length_determinant().unwrap(), 0x100);
    }

    #[test]
    fn extensible_integer_rejects_extension_additions_explicitly() {
        let mut r = AperReader::new(&[0b1000_0000]);
        matches!(
            r.read_extensible_integer(0, 100).unwrap_err(),
            AperError::Unsupported(_)
        );
    }
}
