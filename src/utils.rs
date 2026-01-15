use anyhow::{Result, anyhow, bail};
use casper_types::U512;

const MOTES_PER_CSPR: u64 = 1_000_000_000;

pub fn format_cspr(motes: &U512) -> String {
    let divisor = U512::from(MOTES_PER_CSPR);
    let whole = motes / divisor;
    let fractional = motes % divisor;
    let fractional: u64 = fractional.as_u64();
    format!("{whole}.{fractional:09}")
}

pub fn parse_cspr_to_motes(label: &str, value: &str) -> Result<U512> {
    const MOTES_PER_CSPR: u64 = 1_000_000_000;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} cannot be empty");
    }
    let normalized = trimmed.replace('_', "");
    let (whole, frac) = match normalized.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (normalized.as_str(), ""),
    };
    if whole.is_empty() && frac.is_empty() {
        bail!("{label} is invalid");
    }
    let whole_motes = if whole.is_empty() {
        U512::zero()
    } else {
        U512::from_dec_str(whole)
            .map_err(|_| anyhow!("{label} has invalid digits"))?
            .checked_mul(U512::from(MOTES_PER_CSPR))
            .ok_or_else(|| anyhow!("{label} is too large"))?
    };
    if frac.len() > 9 {
        bail!("{label} supports up to 9 decimal places");
    }
    let mut frac_digits = frac.to_string();
    while frac_digits.len() < 9 {
        frac_digits.push('0');
    }
    let frac_motes = if frac_digits.is_empty() {
        U512::zero()
    } else {
        U512::from_dec_str(&frac_digits).map_err(|_| anyhow!("{label} has invalid digits"))?
    };
    whole_motes
        .checked_add(frac_motes)
        .ok_or_else(|| anyhow!("{label} is too large"))
}

pub fn u512_to_u64(value: U512) -> Result<u64> {
    u64::try_from(value).map_err(|_| anyhow!("payment amount exceeds u64 range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_cspr_zero() {
        assert_eq!(format_cspr(&U512::zero()), "0.000000000");
    }

    #[test]
    fn test_format_cspr_one_cspr() {
        assert_eq!(format_cspr(&U512::from(MOTES_PER_CSPR)), "1.000000000");
    }

    #[test]
    fn test_format_cspr_fractional_only() {
        assert_eq!(format_cspr(&U512::from(123_456_789u64)), "0.123456789");
    }

    #[test]
    fn test_format_cspr_whole_and_fractional() {
        assert_eq!(format_cspr(&U512::from(5_123_456_789u64)), "5.123456789");
    }

    #[test]
    fn test_format_cspr_large_amount() {
        let large = U512::from(1_234_567_890_123_456_789u64);
        assert_eq!(format_cspr(&large), "1234567890.123456789");
    }

    #[test]
    fn test_format_cspr_one_mote() {
        assert_eq!(format_cspr(&U512::one()), "0.000000001");
    }

    #[test]
    fn test_format_cspr_max_fractional() {
        assert_eq!(format_cspr(&U512::from(999_999_999u64)), "0.999999999");
    }

    #[test]
    fn test_format_cspr_very_large() {
        let val = U512::from_dec_str("1000000000000000000000000000").unwrap();
        assert_eq!(format_cspr(&val), "1000000000000000000.000000000");
    }

    #[test]
    fn parses_whole_cspr() {
        assert_eq!(
            parse_cspr_to_motes("amount", "5").expect("motes"),
            U512::from(5_000_000_000u64)
        );
    }

    #[test]
    fn parses_fractional_cspr() {
        assert_eq!(
            parse_cspr_to_motes("amount", "2.5").expect("motes"),
            U512::from(2_500_000_000u64)
        );
        assert_eq!(
            parse_cspr_to_motes("amount", ".5").expect("motes"),
            U512::from(500_000_000u64)
        );
        assert_eq!(
            parse_cspr_to_motes("amount", "0.000000001").expect("motes"),
            U512::from(1u64)
        );
    }

    #[test]
    fn parses_with_underscores() {
        assert_eq!(
            parse_cspr_to_motes("amount", "1_000.000_000_001").expect("motes"),
            U512::from(1_000_000_000_001u64)
        );
    }

    #[test]
    fn rejects_too_many_decimals() {
        let result = parse_cspr_to_motes("amount", "1.0000000001");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_digits() {
        let result = parse_cspr_to_motes("amount", "nope");
        assert!(result.is_err());
    }

    #[test]
    fn max_u64_motes_is_ok() {
        let max_cspr = "18446744073.709551615";
        assert_eq!(
            parse_cspr_to_motes("amount", max_cspr).expect("motes"),
            U512::from(u64::MAX)
        );
    }

    #[test]
    fn rejects_overflowing_values() {
        let over_decimal = "18446744073.709551616";
        let over_whole = "18446744074";
        let over_decimal = parse_cspr_to_motes("amount", over_decimal).expect("motes");
        let over_whole = parse_cspr_to_motes("amount", over_whole).expect("motes");
        assert_eq!(
            over_decimal,
            U512::from_dec_str("18446744073709551616").expect("u512"),
        );
        assert_eq!(
            over_whole,
            U512::from_dec_str("18446744074000000000").expect("u512"),
        );
        assert!(u512_to_u64(over_decimal).is_err());
        assert!(u512_to_u64(over_whole).is_err());
    }

    #[test]
    fn large_nctl_initial_values() {
        let cspr = "1000000000000000000000000000";
        let motes = parse_cspr_to_motes("amount", cspr).expect("motes");
        assert_eq!(
            motes,
            U512::from_dec_str("1000000000000000000000000000000000000").expect("u512")
        );
    }
}
