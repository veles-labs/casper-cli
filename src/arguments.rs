use crate::cl_type::{CLTypeError, parse_cl_type};
use crate::cl_value::{CLValueError, parse_cl_value};
use casper_types::CLValue;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, ArgumentsError>;

#[derive(Debug, Error)]
pub(crate) enum ArgumentsError {
    #[error(transparent)]
    CLType(#[from] CLTypeError),
    #[error(transparent)]
    CLValue(#[from] CLValueError),
    #[error("argument type cannot be empty")]
    ArgumentTypeEmpty,
    #[error("argument name cannot be empty")]
    ArgumentNameEmpty,
    #[error("expected '{delimiter}' in argument")]
    ArgumentMissingDelimiter { delimiter: char },
    #[error("invalid escape sequence")]
    InvalidEscapeSequence,
    #[error("invalid escape sequence '\\{ch}'")]
    InvalidEscapeSequenceChar { ch: char },
}

/// Parse a named argument in the form `name:cltype=value` or `name=value`.
///
/// Escapes:
/// - The name may contain `:`, `=`, or `\` if escaped with a backslash.
/// - The cltype portion does not require escaping but honors `\:` and `\\` for consistency.
///
/// When no cltype is provided, the CLType defaults to `Any` and the value is interpreted
/// as hex bytes (optional `0x` prefix).
pub fn parse_argument(input: &str) -> Result<(String, CLValue)> {
    let (left, value_str) = split_once_unescaped(input, '=')?;
    let (name_raw, cl_type) = match split_once_unescaped(left, ':') {
        Ok((name, cl_type)) => {
            if cl_type.trim().is_empty() {
                return Err(ArgumentsError::ArgumentTypeEmpty);
            }
            (name.to_string(), Some(unescape_argument(cl_type)?))
        }
        Err(_) => (left.to_string(), None),
    };
    let name = unescape_argument(&name_raw)?;
    if name.is_empty() {
        return Err(ArgumentsError::ArgumentNameEmpty);
    }
    let cl_type = cl_type.unwrap_or_else(|| "Any".to_string());
    let bytes = parse_cl_value(&cl_type, value_str)?;
    let cl_type = parse_cl_type(&cl_type)?;
    Ok((name, CLValue::from_components(cl_type, bytes)))
}

fn split_once_unescaped(input: &str, delimiter: char) -> Result<(&str, &str)> {
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == delimiter {
            let (left, right) = input.split_at(idx);
            let right = &right[ch.len_utf8()..];
            return Ok((left, right));
        }
    }
    Err(ArgumentsError::ArgumentMissingDelimiter { delimiter })
}

fn unescape_argument(input: &str) -> Result<String> {
    let mut result = String::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let next = chars.next().ok_or(ArgumentsError::InvalidEscapeSequence)?;
            match next {
                '\\' | ':' | '=' => result.push(next),
                _ => return Err(ArgumentsError::InvalidEscapeSequenceChar { ch: next }),
            }
        } else {
            result.push(ch);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::parse_argument;
    use casper_types::{CLType, CLValue};

    #[test]
    fn parses_argument_with_type() {
        let (name, value) = parse_argument("flag:Bool=true").unwrap();
        assert_eq!(name, "flag");
        assert_eq!(value, CLValue::from_components(CLType::Bool, vec![1]));
    }

    #[test]
    fn parses_argument_without_type() {
        let (name, value) = parse_argument("payload=0xdeadbeef").unwrap();
        assert_eq!(name, "payload");
        assert_eq!(
            value,
            CLValue::from_components(CLType::Any, vec![0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn parses_argument_with_escaped_name() {
        let (name, value) = parse_argument(r"meta\:x\=y:U8=1").unwrap();
        assert_eq!(name, "meta:x=y");
        assert_eq!(value, CLValue::from_components(CLType::U8, vec![1]));
    }

    #[test]
    fn parses_argument_with_account_hash() {
        let input =
            "acct:account_hash=0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let (name, value) = parse_argument(input).unwrap();
        assert_eq!(name, "acct");
        assert_eq!(
            value,
            CLValue::from_components(
                CLType::ByteArray(32),
                vec![
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                ],
            )
        );
    }
}
