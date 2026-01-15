use crate::cl_type::{CLTypeError, MAX_TYPE_NESTING, parse_cl_type};
use casper_types::bytesrepr::{
    FromBytes, OPTION_NONE_TAG, OPTION_SOME_TAG, RESULT_ERR_TAG, RESULT_OK_TAG, ToBytes,
};
use casper_types::crypto::AsymmetricType;
use casper_types::{CLType, CLValue, Key, PublicKey, U128, U256, U512, URef};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CLValueError>;

#[derive(Debug, Error)]
pub enum CLValueError {
    #[error(transparent)]
    ClType(#[from] CLTypeError),
    #[error("value has trailing bytes")]
    ValueTrailingBytes,
    #[error("unit values must be empty or '()'")]
    InvalidUnitValue,
    #[error("invalid Key value: {message}")]
    InvalidKey { message: String },
    #[error("invalid URef value: {message}")]
    InvalidURef { message: String },
    #[error("invalid PublicKey value: {message}")]
    InvalidPublicKey { message: String },
    #[error("any values must be supplied as hex bytes")]
    AnyRequiresHex,
    #[error("type requires hex-encoded bytes")]
    TypeRequiresHex,
    #[error("bool values must be true/false/1/0")]
    InvalidBool,
    #[error("i32 value is out of range or invalid")]
    InvalidI32,
    #[error("i64 value is out of range or invalid")]
    InvalidI64,
    #[error("u8 value is out of range or invalid")]
    InvalidU8,
    #[error("u32 value is out of range or invalid")]
    InvalidU32,
    #[error("u64 value is out of range or invalid")]
    InvalidU64,
    #[error("u128 value is invalid")]
    InvalidU128,
    #[error("u256 value is invalid")]
    InvalidU256,
    #[error("u512 value is invalid")]
    InvalidU512,
    #[error("value is empty")]
    EmptyValue,
    #[error("invalid decimal digit '{ch}'")]
    InvalidDecimalDigit { ch: char },
    #[error("value is missing digits")]
    MissingDigits,
    #[error("unsigned values cannot be negative")]
    UnsignedNegative,
    #[error("hex input has an odd length")]
    OddHexLength,
    #[error("invalid hex input: {message}")]
    InvalidHex { message: String },
    #[error("value is shorter than expected")]
    ValueTooShort,
    #[error("option tag must be 0x00 or 0x01")]
    InvalidOptionTag,
    #[error("result tag must be 0x00 or 0x01")]
    InvalidResultTag,
    #[error("any values are not supported")]
    AnyNotSupported,
    #[error("{label} bytes invalid: {message}")]
    InvalidBytes {
        label: &'static str,
        message: String,
    },
    #[error("value length overflow")]
    ValueLengthOverflow,
    #[error("type nesting exceeds {max}")]
    TypeNestingExceeded { max: usize },
    #[error("byte array length is too large")]
    ByteArrayLengthTooLarge,
    #[error("internal parser error: {message}")]
    Internal { message: &'static str },
}

/// Convert a `CLValue` into a mostly-readable string representation.
pub fn cl_value_to_string(value: &CLValue) -> Result<String> {
    let mut cursor = ValueCursor::new(value.inner_bytes());
    let formatted = format_value(value.cl_type(), &mut cursor, 0)?;
    if !cursor.is_eof() {
        return Err(CLValueError::ValueTrailingBytes);
    }
    Ok(formatted)
}

/// Parse a CL value into bytes using a CLType and string input.
///
/// Input handling depends on the CLType:
/// - Basic types (`Bool`, numeric primitives, `String`, `Key`, `URef`, `PublicKey`, `Unit`) are
///   parsed from human-readable strings.
/// - Composite/generic types (`Option`, `List`, `Result`, `Map`, tuples, `ByteArray`) are parsed
///   from hex-encoded bytes (optional `0x` prefix).
///
/// Special cases:
/// - `Option<T>` accepts the literal `None` (case-insensitive) to emit `OPTION_NONE_TAG`.
/// - `Option<T>` where `T` is a basic type accepts a human-readable value for `Some(T)`;
///   to force raw hex bytes for `Option<T>`, prefix with `0x`.
/// - `Bool` accepts `true`, `false`, `1`, `0`.
/// - Integers are decimal, allow `_` separators, and signed/unsigned rules apply.
/// - `Key` and `URef` accept their formatted string forms.
/// - `PublicKey` accepts the tagged hex form used by `casper-types`.
/// - `Any` accepts hex bytes without validation.
///
/// Aliases (case-insensitive, `_`/`-` ignored): `account_hash` => `ByteArray[32]`,
/// `byte_array` => `ByteArray[...]`, `public_key` => `PublicKey`.
///
/// Any trailing bytes in hex input will cause an error.
///
/// Compared to `casper-client`'s argument format, this parser does not require
/// per-type ad hoc names (like `opt_i32`) and supports full nested CLType syntax.
pub fn parse_cl_value(cl_type: &str, input: &str) -> Result<Vec<u8>> {
    let cl_type = parse_cl_type(cl_type)?;
    let trimmed = input.trim();
    // Accept a textual "None" for Option<T> to avoid forcing hex for the common case.
    if let CLType::Option(inner) = &cl_type {
        if trimmed.eq_ignore_ascii_case("none") {
            return Ok(vec![OPTION_NONE_TAG]);
        }
        let has_hex_prefix = trimmed.starts_with("0x") || trimmed.starts_with("0X");
        if !has_hex_prefix && !requires_hex_value(inner.as_ref()) {
            let inner_bytes = parse_basic_value(inner.as_ref(), trimmed)?;
            let mut bytes = Vec::with_capacity(1 + inner_bytes.len());
            bytes.push(OPTION_SOME_TAG);
            bytes.extend_from_slice(&inner_bytes);
            return Ok(bytes);
        }
    }
    if matches!(cl_type, CLType::Any) {
        return parse_hex_input(input);
    }
    if requires_hex_value(&cl_type) {
        let bytes = parse_hex_input(input)?;
        let mut cursor = ValueCursor::new(&bytes);
        // Validate the hex bytes against the expected CLType structure.
        validate_bytes_for_cl_type(&cl_type, &mut cursor)?;
        if !cursor.is_eof() {
            return Err(CLValueError::ValueTrailingBytes);
        }
        Ok(bytes)
    } else {
        parse_basic_value(&cl_type, input)
    }
}

fn requires_hex_value(cl_type: &CLType) -> bool {
    !matches!(
        cl_type,
        CLType::Bool
            | CLType::I32
            | CLType::I64
            | CLType::U8
            | CLType::U32
            | CLType::U64
            | CLType::U128
            | CLType::U256
            | CLType::U512
            | CLType::Unit
            | CLType::String
            | CLType::Key
            | CLType::URef
            | CLType::PublicKey
    )
}

fn to_bytes_label<T: ToBytes>(value: &T, label: &'static str) -> Result<Vec<u8>> {
    value.to_bytes().map_err(|err| CLValueError::InvalidBytes {
        label,
        message: err.to_string(),
    })
}

fn parse_basic_value(cl_type: &CLType, input: &str) -> Result<Vec<u8>> {
    match cl_type {
        CLType::Bool => {
            let value = parse_bool(input)?;
            to_bytes_label(&value, "bool")
        }
        CLType::I32 => {
            let value = parse_i32(input)?;
            to_bytes_label(&value, "i32")
        }
        CLType::I64 => {
            let value = parse_i64(input)?;
            to_bytes_label(&value, "i64")
        }
        CLType::U8 => {
            let value = parse_u8(input)?;
            to_bytes_label(&value, "u8")
        }
        CLType::U32 => {
            let value = parse_u32(input)?;
            to_bytes_label(&value, "u32")
        }
        CLType::U64 => {
            let value = parse_u64(input)?;
            to_bytes_label(&value, "u64")
        }
        CLType::U128 => {
            let value = parse_u128(input)?;
            to_bytes_label(&value, "u128")
        }
        CLType::U256 => {
            let value = parse_u256(input)?;
            to_bytes_label(&value, "u256")
        }
        CLType::U512 => {
            let value = parse_u512(input)?;
            to_bytes_label(&value, "u512")
        }
        CLType::Unit => {
            let trimmed = input.trim();
            if trimmed.is_empty() || trimmed == "()" || trimmed.eq_ignore_ascii_case("unit") {
                Ok(Vec::new())
            } else {
                Err(CLValueError::InvalidUnitValue)
            }
        }
        CLType::String => to_bytes_label(&input.to_string(), "string"),
        CLType::Key => {
            let trimmed = input.trim();
            let value =
                Key::from_formatted_str(trimmed).map_err(|err| CLValueError::InvalidKey {
                    message: err.to_string(),
                })?;
            to_bytes_label(&value, "key")
        }
        CLType::URef => {
            let trimmed = input.trim();
            let value =
                URef::from_formatted_str(trimmed).map_err(|err| CLValueError::InvalidURef {
                    message: err.to_string(),
                })?;
            to_bytes_label(&value, "uref")
        }
        CLType::PublicKey => {
            let hex = normalize_hex_input(input);
            let value = PublicKey::from_hex(hex.as_bytes()).map_err(|err| {
                CLValueError::InvalidPublicKey {
                    message: err.to_string(),
                }
            })?;
            to_bytes_label(&value, "public-key")
        }
        CLType::Any => Err(CLValueError::AnyRequiresHex),
        _ => Err(CLValueError::TypeRequiresHex),
    }
}

fn parse_bool(input: &str) -> Result<bool> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(CLValueError::InvalidBool),
    }
}

fn parse_i32(input: &str) -> Result<i32> {
    let normalized = normalize_decimal(input)?;
    normalized
        .parse::<i32>()
        .map_err(|_| CLValueError::InvalidI32)
}

fn parse_i64(input: &str) -> Result<i64> {
    let normalized = normalize_decimal(input)?;
    normalized
        .parse::<i64>()
        .map_err(|_| CLValueError::InvalidI64)
}

fn parse_u8(input: &str) -> Result<u8> {
    let normalized = normalize_unsigned_decimal(input)?;
    normalized
        .parse::<u8>()
        .map_err(|_| CLValueError::InvalidU8)
}

fn parse_u32(input: &str) -> Result<u32> {
    let normalized = normalize_unsigned_decimal(input)?;
    normalized
        .parse::<u32>()
        .map_err(|_| CLValueError::InvalidU32)
}

fn parse_u64(input: &str) -> Result<u64> {
    let normalized = normalize_unsigned_decimal(input)?;
    normalized
        .parse::<u64>()
        .map_err(|_| CLValueError::InvalidU64)
}

fn parse_u128(input: &str) -> Result<U128> {
    let normalized = normalize_unsigned_decimal(input)?;
    U128::from_dec_str(&normalized).map_err(|_| CLValueError::InvalidU128)
}

fn parse_u256(input: &str) -> Result<U256> {
    let normalized = normalize_unsigned_decimal(input)?;
    U256::from_dec_str(&normalized).map_err(|_| CLValueError::InvalidU256)
}

fn parse_u512(input: &str) -> Result<U512> {
    let normalized = normalize_unsigned_decimal(input)?;
    U512::from_dec_str(&normalized).map_err(|_| CLValueError::InvalidU512)
}

fn normalize_decimal(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CLValueError::EmptyValue);
    }
    let mut normalized = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        if ch == '_' {
            continue;
        }
        if (ch == '-' || ch == '+') && idx == 0 {
            normalized.push(ch);
            continue;
        }
        if ch.is_ascii_digit() {
            normalized.push(ch);
        } else {
            return Err(CLValueError::InvalidDecimalDigit { ch });
        }
    }
    if normalized == "-" || normalized == "+" {
        return Err(CLValueError::MissingDigits);
    }
    Ok(normalized)
}

fn normalize_unsigned_decimal(input: &str) -> Result<String> {
    let normalized = normalize_decimal(input)?;
    if normalized.starts_with('-') {
        return Err(CLValueError::UnsignedNegative);
    }
    Ok(normalized.trim_start_matches('+').to_string())
}

fn parse_hex_input(input: &str) -> Result<Vec<u8>> {
    let normalized = normalize_hex_input(input);
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    if normalized.len() % 2 != 0 {
        return Err(CLValueError::OddHexLength);
    }
    hex::decode(&normalized).map_err(|err| CLValueError::InvalidHex {
        message: err.to_string(),
    })
}

fn normalize_hex_input(input: &str) -> String {
    let trimmed = input.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    trimmed
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '_')
        .collect()
}

// Cursor over a byte slice used to validate hex-encoded values without recursion.
struct ValueCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ValueCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.bytes.len().saturating_sub(self.pos) < len {
            return Err(CLValueError::ValueTooShort);
        }
        let start = self.pos;
        let end = start + len;
        self.pos = end;
        Ok(&self.bytes[start..end])
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(buf))
    }

    fn take_remaining(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.bytes.len();
        &self.bytes[start..]
    }
}

fn format_value(cl_type: &CLType, cursor: &mut ValueCursor<'_>, depth: usize) -> Result<String> {
    if depth > MAX_TYPE_NESTING {
        return Err(CLValueError::TypeNestingExceeded {
            max: MAX_TYPE_NESTING,
        });
    }
    match cl_type {
        CLType::Bool => Ok(read_from_bytes::<bool>(cursor, "bool")?.to_string()),
        CLType::I32 => Ok(read_from_bytes::<i32>(cursor, "i32")?.to_string()),
        CLType::I64 => Ok(read_from_bytes::<i64>(cursor, "i64")?.to_string()),
        CLType::U8 => Ok(read_from_bytes::<u8>(cursor, "u8")?.to_string()),
        CLType::U32 => Ok(read_from_bytes::<u32>(cursor, "u32")?.to_string()),
        CLType::U64 => Ok(read_from_bytes::<u64>(cursor, "u64")?.to_string()),
        CLType::U128 => Ok(read_from_bytes::<U128>(cursor, "u128")?.to_string()),
        CLType::U256 => Ok(read_from_bytes::<U256>(cursor, "u256")?.to_string()),
        CLType::U512 => Ok(read_from_bytes::<U512>(cursor, "u512")?.to_string()),
        CLType::Unit => Ok("()".to_string()),
        CLType::String => Ok(format_string_value(&read_from_bytes::<String>(
            cursor, "string",
        )?)),
        CLType::Key => Ok(read_from_bytes::<Key>(cursor, "key")?.to_formatted_string()),
        CLType::URef => Ok(read_from_bytes::<URef>(cursor, "uref")?.to_formatted_string()),
        CLType::PublicKey => {
            Ok(read_from_bytes::<PublicKey>(cursor, "public-key")?.to_hex_string())
        }
        CLType::Option(inner) => {
            let tag = cursor.take_u8()?;
            match tag {
                OPTION_NONE_TAG => Ok("None".to_string()),
                OPTION_SOME_TAG => {
                    let inner_value = format_value(inner.as_ref(), cursor, depth + 1)?;
                    Ok(format!("Some({inner_value})"))
                }
                _ => Err(CLValueError::InvalidOptionTag),
            }
        }
        CLType::List(inner) => {
            let length = cursor.take_u32()?;
            let length = usize::try_from(length).map_err(|_| CLValueError::ValueLengthOverflow)?;
            let mut items = Vec::with_capacity(length);
            for _ in 0..length {
                items.push(format_value(inner.as_ref(), cursor, depth + 1)?);
            }
            Ok(format!("[{}]", items.join(", ")))
        }
        CLType::ByteArray(length) => {
            let len =
                usize::try_from(*length).map_err(|_| CLValueError::ByteArrayLengthTooLarge)?;
            let bytes = cursor.take(len)?;
            Ok(format!("0x{}", hex::encode(bytes)))
        }
        CLType::Result { ok, err } => {
            let tag = cursor.take_u8()?;
            match tag {
                RESULT_OK_TAG => {
                    let value = format_value(ok.as_ref(), cursor, depth + 1)?;
                    Ok(format!("Ok({value})"))
                }
                RESULT_ERR_TAG => {
                    let value = format_value(err.as_ref(), cursor, depth + 1)?;
                    Ok(format!("Err({value})"))
                }
                _ => Err(CLValueError::InvalidResultTag),
            }
        }
        CLType::Map { key, value } => {
            let length = cursor.take_u32()?;
            let length = usize::try_from(length).map_err(|_| CLValueError::ValueLengthOverflow)?;
            let mut entries = Vec::with_capacity(length);
            for _ in 0..length {
                let key_value = format_value(key.as_ref(), cursor, depth + 1)?;
                let value_value = format_value(value.as_ref(), cursor, depth + 1)?;
                entries.push(format!("{key_value}: {value_value}"));
            }
            Ok(format!("{{{}}}", entries.join(", ")))
        }
        CLType::Tuple1([t1]) => {
            let value = format_value(t1.as_ref(), cursor, depth + 1)?;
            Ok(format!("({value},)"))
        }
        CLType::Tuple2([t1, t2]) => {
            let first = format_value(t1.as_ref(), cursor, depth + 1)?;
            let second = format_value(t2.as_ref(), cursor, depth + 1)?;
            Ok(format!("({first}, {second})"))
        }
        CLType::Tuple3([t1, t2, t3]) => {
            let first = format_value(t1.as_ref(), cursor, depth + 1)?;
            let second = format_value(t2.as_ref(), cursor, depth + 1)?;
            let third = format_value(t3.as_ref(), cursor, depth + 1)?;
            Ok(format!("({first}, {second}, {third})"))
        }
        CLType::Any => {
            if depth > 0 {
                return Err(CLValueError::AnyNotSupported);
            }
            let bytes = cursor.take_remaining();
            Ok(format!("0x{}", hex::encode(bytes)))
        }
    }
}

fn format_string_value(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return value.to_string();
    }
    let escaped: String = value.chars().flat_map(|ch| ch.escape_default()).collect();
    format!("\"{escaped}\"")
}

#[derive(Clone, Copy)]
enum ValueTask<'a> {
    Type(&'a CLType),
    List {
        element: &'a CLType,
        remaining: u32,
    },
    Map {
        key: &'a CLType,
        value: &'a CLType,
        remaining: u32,
        expecting_key: bool,
    },
}

fn validate_bytes_for_cl_type<'a>(cl_type: &'a CLType, cursor: &mut ValueCursor<'a>) -> Result<()> {
    // Stack-based walk avoids deep recursion on nested CLTypes.
    let mut stack = vec![ValueTask::Type(cl_type)];
    while let Some(task) = stack.pop() {
        match task {
            ValueTask::Type(cl_type) => match cl_type {
                CLType::Bool => consume_from_bytes::<bool>(cursor, "bool")?,
                CLType::I32 => consume_from_bytes::<i32>(cursor, "i32")?,
                CLType::I64 => consume_from_bytes::<i64>(cursor, "i64")?,
                CLType::U8 => consume_from_bytes::<u8>(cursor, "u8")?,
                CLType::U32 => consume_from_bytes::<u32>(cursor, "u32")?,
                CLType::U64 => consume_from_bytes::<u64>(cursor, "u64")?,
                CLType::U128 => consume_from_bytes::<U128>(cursor, "u128")?,
                CLType::U256 => consume_from_bytes::<U256>(cursor, "u256")?,
                CLType::U512 => consume_from_bytes::<U512>(cursor, "u512")?,
                CLType::Unit => {}
                CLType::String => consume_from_bytes::<String>(cursor, "string")?,
                CLType::Key => consume_from_bytes::<Key>(cursor, "key")?,
                CLType::URef => consume_from_bytes::<URef>(cursor, "uref")?,
                CLType::PublicKey => consume_from_bytes::<PublicKey>(cursor, "public-key")?,
                CLType::Option(inner) => {
                    let tag = cursor.take_u8()?;
                    match tag {
                        OPTION_NONE_TAG => {}
                        OPTION_SOME_TAG => stack.push(ValueTask::Type(inner.as_ref())),
                        _ => return Err(CLValueError::InvalidOptionTag),
                    }
                }
                CLType::List(inner) => {
                    let length = cursor.take_u32()?;
                    stack.push(ValueTask::List {
                        element: inner.as_ref(),
                        remaining: length,
                    });
                }
                CLType::ByteArray(length) => {
                    let len = usize::try_from(*length)
                        .map_err(|_| CLValueError::ByteArrayLengthTooLarge)?;
                    cursor.take(len)?;
                }
                CLType::Result { ok, err } => {
                    let tag = cursor.take_u8()?;
                    match tag {
                        RESULT_ERR_TAG => stack.push(ValueTask::Type(err.as_ref())),
                        RESULT_OK_TAG => stack.push(ValueTask::Type(ok.as_ref())),
                        _ => return Err(CLValueError::InvalidResultTag),
                    }
                }
                CLType::Map { key, value } => {
                    let length = cursor.take_u32()?;
                    stack.push(ValueTask::Map {
                        key: key.as_ref(),
                        value: value.as_ref(),
                        remaining: length,
                        expecting_key: true,
                    });
                }
                CLType::Tuple1([t1]) => stack.push(ValueTask::Type(t1.as_ref())),
                CLType::Tuple2([t1, t2]) => {
                    stack.push(ValueTask::Type(t2.as_ref()));
                    stack.push(ValueTask::Type(t1.as_ref()));
                }
                CLType::Tuple3([t1, t2, t3]) => {
                    stack.push(ValueTask::Type(t3.as_ref()));
                    stack.push(ValueTask::Type(t2.as_ref()));
                    stack.push(ValueTask::Type(t1.as_ref()));
                }
                CLType::Any => return Err(CLValueError::AnyNotSupported),
            },
            ValueTask::List { element, remaining } => {
                if remaining == 0 {
                    continue;
                }
                stack.push(ValueTask::List {
                    element,
                    remaining: remaining - 1,
                });
                stack.push(ValueTask::Type(element));
            }
            ValueTask::Map {
                key,
                value,
                remaining,
                expecting_key,
            } => {
                if remaining == 0 {
                    continue;
                }
                if expecting_key {
                    stack.push(ValueTask::Map {
                        key,
                        value,
                        remaining,
                        expecting_key: false,
                    });
                    stack.push(ValueTask::Type(key));
                } else {
                    stack.push(ValueTask::Map {
                        key,
                        value,
                        remaining: remaining - 1,
                        expecting_key: true,
                    });
                    stack.push(ValueTask::Type(value));
                }
            }
        }
    }
    Ok(())
}

fn read_from_bytes<T: FromBytes>(cursor: &mut ValueCursor<'_>, label: &'static str) -> Result<T> {
    let remaining = cursor.remaining_slice();
    let (value, remainder) =
        T::from_bytes(remaining).map_err(|err| CLValueError::InvalidBytes {
            label,
            message: err.to_string(),
        })?;
    let consumed = remaining
        .len()
        .checked_sub(remainder.len())
        .ok_or(CLValueError::Internal {
            message: "invalid remainder length",
        })?;
    cursor.pos = cursor
        .pos
        .checked_add(consumed)
        .ok_or(CLValueError::ValueLengthOverflow)?;
    Ok(value)
}

fn consume_from_bytes<T: FromBytes>(
    cursor: &mut ValueCursor<'_>,
    label: &'static str,
) -> Result<()> {
    let remaining = cursor.remaining_slice();
    let (_value, remainder) =
        T::from_bytes(remaining).map_err(|err| CLValueError::InvalidBytes {
            label,
            message: err.to_string(),
        })?;
    let consumed = remaining
        .len()
        .checked_sub(remainder.len())
        .ok_or(CLValueError::Internal {
            message: "invalid remainder length",
        })?;
    cursor.pos = cursor
        .pos
        .checked_add(consumed)
        .ok_or(CLValueError::ValueLengthOverflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{cl_value_to_string, parse_cl_value};
    use crate::cl_type::MAX_TYPE_NESTING;
    use crate::cl_type::cl_type_to_string;
    use casper_types::bytesrepr::{
        OPTION_NONE_TAG, OPTION_SOME_TAG, RESULT_ERR_TAG, RESULT_OK_TAG, ToBytes,
    };
    use casper_types::crypto::AsymmetricType;
    use casper_types::{AccessRights, CLType, CLValue, Key, PublicKey, U128, U256, U512, URef};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug)]
    struct GenValue {
        cl_type: CLType,
        bytes: Vec<u8>,
        input: String,
    }

    fn cl_type_value_strategy() -> impl Strategy<Value = CLType> {
        let leaf = prop_oneof![
            Just(CLType::Bool),
            Just(CLType::I32),
            Just(CLType::I64),
            Just(CLType::U8),
            Just(CLType::U32),
            Just(CLType::U64),
            Just(CLType::U128),
            Just(CLType::U256),
            Just(CLType::U512),
            Just(CLType::Unit),
            Just(CLType::String),
            Just(CLType::Key),
            Just(CLType::URef),
            Just(CLType::PublicKey),
            (0u32..=16).prop_map(CLType::ByteArray),
        ];

        leaf.prop_recursive(4, 32, 8, |inner| {
            prop_oneof![
                inner.clone().prop_map(|t| CLType::Option(Box::new(t))),
                inner.clone().prop_map(|t| CLType::List(Box::new(t))),
                (inner.clone(), inner.clone()).prop_map(|(ok, err)| CLType::Result {
                    ok: Box::new(ok),
                    err: Box::new(err),
                }),
                (inner.clone(), inner.clone()).prop_map(|(key, value)| CLType::Map {
                    key: Box::new(key),
                    value: Box::new(value),
                }),
                inner.clone().prop_map(|t| CLType::Tuple1([Box::new(t)])),
                (inner.clone(), inner.clone())
                    .prop_map(|(t1, t2)| CLType::Tuple2([Box::new(t1), Box::new(t2)])),
                (inner.clone(), inner.clone(), inner.clone()).prop_map(|(t1, t2, t3)| {
                    CLType::Tuple3([Box::new(t1), Box::new(t2), Box::new(t3)])
                }),
            ]
        })
    }

    fn cl_value_strategy() -> impl Strategy<Value = GenValue> {
        cl_type_value_strategy().prop_flat_map(value_for_type)
    }

    fn value_for_type(cl_type: CLType) -> BoxedStrategy<GenValue> {
        match cl_type {
            CLType::Bool => any::<bool>()
                .prop_map(|value| GenValue {
                    cl_type: CLType::Bool,
                    bytes: value.to_bytes().unwrap(),
                    input: if value {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    },
                })
                .boxed(),
            CLType::I32 => any::<i32>()
                .prop_map(|value| GenValue {
                    cl_type: CLType::I32,
                    bytes: value.to_bytes().unwrap(),
                    input: value.to_string(),
                })
                .boxed(),
            CLType::I64 => any::<i64>()
                .prop_map(|value| GenValue {
                    cl_type: CLType::I64,
                    bytes: value.to_bytes().unwrap(),
                    input: value.to_string(),
                })
                .boxed(),
            CLType::U8 => any::<u8>()
                .prop_map(|value| GenValue {
                    cl_type: CLType::U8,
                    bytes: value.to_bytes().unwrap(),
                    input: value.to_string(),
                })
                .boxed(),
            CLType::U32 => any::<u32>()
                .prop_map(|value| GenValue {
                    cl_type: CLType::U32,
                    bytes: value.to_bytes().unwrap(),
                    input: value.to_string(),
                })
                .boxed(),
            CLType::U64 => any::<u64>()
                .prop_map(|value| GenValue {
                    cl_type: CLType::U64,
                    bytes: value.to_bytes().unwrap(),
                    input: value.to_string(),
                })
                .boxed(),
            CLType::U128 => any::<u128>()
                .prop_map(|value| {
                    let value = U128::from(value);
                    GenValue {
                        cl_type: CLType::U128,
                        bytes: value.to_bytes().unwrap(),
                        input: value.to_string(),
                    }
                })
                .boxed(),
            CLType::U256 => any::<u128>()
                .prop_map(|value| {
                    let value = U256::from(value);
                    GenValue {
                        cl_type: CLType::U256,
                        bytes: value.to_bytes().unwrap(),
                        input: value.to_string(),
                    }
                })
                .boxed(),
            CLType::U512 => any::<u128>()
                .prop_map(|value| {
                    let value = U512::from(value);
                    GenValue {
                        cl_type: CLType::U512,
                        bytes: value.to_bytes().unwrap(),
                        input: value.to_string(),
                    }
                })
                .boxed(),
            CLType::Unit => Just(GenValue {
                cl_type: CLType::Unit,
                bytes: Vec::new(),
                input: String::new(),
            })
            .boxed(),
            CLType::String => proptest::collection::vec(b'a'..=b'z', 0..16)
                .prop_map(|bytes| {
                    let value = String::from_utf8(bytes).unwrap();
                    GenValue {
                        cl_type: CLType::String,
                        bytes: value.to_bytes().unwrap(),
                        input: value,
                    }
                })
                .boxed(),
            CLType::Key => proptest::array::uniform32(any::<u8>())
                .prop_map(|addr| {
                    let key = Key::Hash(addr);
                    let input = key.to_formatted_string();
                    GenValue {
                        cl_type: CLType::Key,
                        bytes: key.to_bytes().unwrap(),
                        input,
                    }
                })
                .boxed(),
            CLType::URef => proptest::array::uniform32(any::<u8>())
                .prop_map(|addr| {
                    let uref = URef::new(addr, AccessRights::READ);
                    let input = uref.to_formatted_string();
                    GenValue {
                        cl_type: CLType::URef,
                        bytes: uref.to_bytes().unwrap(),
                        input,
                    }
                })
                .boxed(),
            CLType::PublicKey => prop_oneof![
                Just(PublicKey::System),
                Just(PublicKey::ed25519_from_bytes([1u8; 32]).unwrap()),
            ]
            .prop_map(|key| {
                let input = key.to_hex();
                GenValue {
                    cl_type: CLType::PublicKey,
                    bytes: key.to_bytes().unwrap(),
                    input,
                }
            })
            .boxed(),
            CLType::Option(inner) => {
                let inner_type = *inner;
                prop_oneof![
                    Just({
                        let bytes = vec![OPTION_NONE_TAG];
                        GenValue {
                            cl_type: CLType::Option(Box::new(inner_type.clone())),
                            input: format!("0x{}", hex::encode(&bytes)),
                            bytes,
                        }
                    }),
                    value_for_type(inner_type.clone()).prop_map(move |inner_value| {
                        let mut bytes = Vec::with_capacity(1 + inner_value.bytes.len());
                        bytes.push(OPTION_SOME_TAG);
                        bytes.extend_from_slice(&inner_value.bytes);
                        GenValue {
                            cl_type: CLType::Option(Box::new(inner_type.clone())),
                            input: format!("0x{}", hex::encode(&bytes)),
                            bytes,
                        }
                    }),
                ]
                .boxed()
            }
            CLType::List(inner) => {
                let inner_type = *inner;
                proptest::collection::vec(value_for_type(inner_type.clone()), 0..4)
                    .prop_map(move |items| {
                        let mut bytes = Vec::new();
                        bytes.extend_from_slice(&(items.len() as u32).to_le_bytes());
                        for item in items {
                            bytes.extend_from_slice(&item.bytes);
                        }
                        GenValue {
                            cl_type: CLType::List(Box::new(inner_type.clone())),
                            input: hex::encode(&bytes),
                            bytes,
                        }
                    })
                    .boxed()
            }
            CLType::ByteArray(len) => {
                let length = len as usize;
                proptest::collection::vec(any::<u8>(), length..=length)
                    .prop_map(move |bytes| GenValue {
                        cl_type: CLType::ByteArray(len),
                        input: hex::encode(&bytes),
                        bytes,
                    })
                    .boxed()
            }
            CLType::Result { ok, err } => {
                let ok_type = *ok;
                let err_type = *err;
                let ok_type_for_ok = ok_type.clone();
                let err_type_for_ok = err_type.clone();
                let ok_type_for_err = ok_type.clone();
                let err_type_for_err = err_type.clone();
                prop_oneof![
                    value_for_type(ok_type.clone()).prop_map(move |ok_value| {
                        let mut bytes = Vec::with_capacity(1 + ok_value.bytes.len());
                        bytes.push(RESULT_OK_TAG);
                        bytes.extend_from_slice(&ok_value.bytes);
                        GenValue {
                            cl_type: CLType::Result {
                                ok: Box::new(ok_type_for_ok.clone()),
                                err: Box::new(err_type_for_ok.clone()),
                            },
                            input: hex::encode(&bytes),
                            bytes,
                        }
                    }),
                    value_for_type(err_type.clone()).prop_map(move |err_value| {
                        let mut bytes = Vec::with_capacity(1 + err_value.bytes.len());
                        bytes.push(RESULT_ERR_TAG);
                        bytes.extend_from_slice(&err_value.bytes);
                        GenValue {
                            cl_type: CLType::Result {
                                ok: Box::new(ok_type_for_err.clone()),
                                err: Box::new(err_type_for_err.clone()),
                            },
                            input: hex::encode(&bytes),
                            bytes,
                        }
                    }),
                ]
                .boxed()
            }
            CLType::Map { key, value } => {
                let key_type = *key;
                let value_type = *value;
                proptest::collection::vec(
                    (
                        value_for_type(key_type.clone()),
                        value_for_type(value_type.clone()),
                    ),
                    0..4,
                )
                .prop_map(move |items| {
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&(items.len() as u32).to_le_bytes());
                    for (key_value, value_value) in items {
                        bytes.extend_from_slice(&key_value.bytes);
                        bytes.extend_from_slice(&value_value.bytes);
                    }
                    GenValue {
                        cl_type: CLType::Map {
                            key: Box::new(key_type.clone()),
                            value: Box::new(value_type.clone()),
                        },
                        input: hex::encode(&bytes),
                        bytes,
                    }
                })
                .boxed()
            }
            CLType::Tuple1([t1]) => {
                let t1_type = *t1;
                value_for_type(t1_type.clone())
                    .prop_map(move |value| GenValue {
                        cl_type: CLType::Tuple1([Box::new(t1_type.clone())]),
                        input: hex::encode(&value.bytes),
                        bytes: value.bytes,
                    })
                    .boxed()
            }
            CLType::Tuple2([t1, t2]) => {
                let t1_type = *t1;
                let t2_type = *t2;
                (
                    value_for_type(t1_type.clone()),
                    value_for_type(t2_type.clone()),
                )
                    .prop_map(move |(v1, v2)| {
                        let mut bytes = Vec::with_capacity(v1.bytes.len() + v2.bytes.len());
                        bytes.extend_from_slice(&v1.bytes);
                        bytes.extend_from_slice(&v2.bytes);
                        GenValue {
                            cl_type: CLType::Tuple2([
                                Box::new(t1_type.clone()),
                                Box::new(t2_type.clone()),
                            ]),
                            input: hex::encode(&bytes),
                            bytes,
                        }
                    })
                    .boxed()
            }
            CLType::Tuple3([t1, t2, t3]) => {
                let t1_type = *t1;
                let t2_type = *t2;
                let t3_type = *t3;
                (
                    value_for_type(t1_type.clone()),
                    value_for_type(t2_type.clone()),
                    value_for_type(t3_type.clone()),
                )
                    .prop_map(move |(v1, v2, v3)| {
                        let mut bytes =
                            Vec::with_capacity(v1.bytes.len() + v2.bytes.len() + v3.bytes.len());
                        bytes.extend_from_slice(&v1.bytes);
                        bytes.extend_from_slice(&v2.bytes);
                        bytes.extend_from_slice(&v3.bytes);
                        GenValue {
                            cl_type: CLType::Tuple3([
                                Box::new(t1_type.clone()),
                                Box::new(t2_type.clone()),
                                Box::new(t3_type.clone()),
                            ]),
                            input: hex::encode(&bytes),
                            bytes,
                        }
                    })
                    .boxed()
            }
            CLType::Any => unreachable!("Any is not generated in cl_type_value_strategy"),
        }
    }

    proptest! {
        #[test]
        fn roundtrip_cl_value(case in cl_value_strategy()) {
            let cl_type = cl_type_to_string(&case.cl_type);
            let parsed = parse_cl_value(&cl_type, &case.input).unwrap();
            prop_assert_eq!(parsed, case.bytes);
        }
    }

    #[test]
    fn parses_basic_values() {
        assert_eq!(parse_cl_value("Bool", "true").unwrap(), vec![1]);
        assert_eq!(
            parse_cl_value("String", "abc").unwrap(),
            "abc".to_string().to_bytes().unwrap()
        );
        assert_eq!(
            parse_cl_value("u64", "1234").unwrap(),
            1234u64.to_bytes().unwrap()
        );
    }

    #[test]
    fn parses_key_value() {
        let key = Key::Hash([2u8; 32]);
        let input = key.to_formatted_string();
        assert_eq!(
            parse_cl_value("Key", &input).unwrap(),
            key.to_bytes().unwrap()
        );
    }

    #[test]
    fn parses_account_hash_value() {
        let input = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let bytes = parse_cl_value("account_hash", input).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[31], 0x20);
    }

    #[test]
    fn parses_uref_value() {
        let uref = URef::new([3u8; 32], AccessRights::READ);
        let input = uref.to_formatted_string();
        assert_eq!(
            parse_cl_value("URef", &input).unwrap(),
            uref.to_bytes().unwrap()
        );
    }

    #[test]
    fn parses_public_key_value() {
        let public_key = PublicKey::ed25519_from_bytes([1u8; 32]).unwrap();
        let input = public_key.to_hex();
        assert_eq!(
            parse_cl_value("PublicKey", &input).unwrap(),
            public_key.to_bytes().unwrap()
        );
    }

    #[test]
    fn parses_option_value_hex() {
        assert_eq!(
            parse_cl_value("Option<Bool>", "0x0101").unwrap(),
            vec![1, 1]
        );
    }

    #[test]
    fn parses_option_none_literal() {
        assert_eq!(parse_cl_value("Option<Bool>", "None").unwrap(), vec![0]);
        assert_eq!(parse_cl_value("Option<Bool>", "none").unwrap(), vec![0]);
    }

    #[test]
    fn rejects_invalid_option_tag() {
        assert!(parse_cl_value("Option<Bool>", "0x02").is_err());
    }

    #[test]
    fn parses_nested_result_option_hex() {
        let value: Result<Option<u64>, u64> = Ok(Some(7));
        let bytes = value.to_bytes().unwrap();
        let hex = hex::encode(&bytes);
        assert_eq!(
            parse_cl_value("Result<Option<U64>, U64>", &hex).unwrap(),
            bytes
        );
    }

    #[test]
    fn parses_result_err_hex() {
        let value: Result<Option<u64>, u64> = Err(9);
        let bytes = value.to_bytes().unwrap();
        let hex = hex::encode(&bytes);
        assert_eq!(
            parse_cl_value("Result<Option<U64>, U64>", &hex).unwrap(),
            bytes
        );
    }

    #[test]
    fn parses_list_u8_hex() {
        let value = casper_types::bytesrepr::Bytes::from(vec![1u8, 2, 3]);
        let bytes = value.to_bytes().unwrap();
        let hex = hex::encode(&bytes);
        assert_eq!(parse_cl_value("List<U8>", &hex).unwrap(), bytes);
    }

    #[test]
    fn parses_map_string_u32_hex() {
        let mut map = BTreeMap::new();
        map.insert("alpha".to_string(), 1u32);
        map.insert("beta".to_string(), 2u32);
        let bytes = map.to_bytes().unwrap();
        let hex = hex::encode(&bytes);
        assert_eq!(parse_cl_value("Map<String, U32>", &hex).unwrap(), bytes);
    }

    #[test]
    fn parses_tuple3_hex() {
        let value = (true, 7u32, "hi".to_string());
        let bytes = value.to_bytes().unwrap();
        let hex = hex::encode(&bytes);
        assert_eq!(parse_cl_value("(Bool, U32, String)", &hex).unwrap(), bytes);
    }

    #[test]
    fn rejects_short_byte_array() {
        assert!(parse_cl_value("ByteArray[4]", "0x0102").is_err());
    }

    #[test]
    fn rejects_list_length_mismatch() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[1u8, 2u8]);
        let hex = hex::encode(&bytes);
        assert!(parse_cl_value("List<U8>", &hex).is_err());
    }

    #[test]
    fn rejects_value_over_max_type_nesting() {
        let mut cl_type = "Bool".to_string();
        for _ in 0..=MAX_TYPE_NESTING {
            cl_type = format!("Option<{cl_type}>");
        }
        assert!(parse_cl_value(&cl_type, "0x00").is_err());
    }

    #[test]
    fn parses_signed_integers() {
        assert_eq!(
            parse_cl_value("i32", "-1").unwrap(),
            (-1i32).to_bytes().unwrap()
        );
        assert_eq!(
            parse_cl_value("i64", "9223372036854775807").unwrap(),
            i64::MAX.to_bytes().unwrap()
        );
    }

    #[test]
    fn rejects_signed_integer_overflow_underflow() {
        let i32_over = format!("{}", i32::MAX as i64 + 1);
        let i32_under = format!("{}", i32::MIN as i64 - 1);
        assert!(parse_cl_value("i32", &i32_over).is_err());
        assert!(parse_cl_value("i32", &i32_under).is_err());

        let i64_over = format!("{}", i64::MAX as i128 + 1);
        let i64_under = format!("{}", i64::MIN as i128 - 1);
        assert!(parse_cl_value("i64", &i64_over).is_err());
        assert!(parse_cl_value("i64", &i64_under).is_err());
    }

    #[test]
    fn parses_unsigned_integers() {
        assert_eq!(
            parse_cl_value("u8", "255").unwrap(),
            255u8.to_bytes().unwrap()
        );
        assert_eq!(
            parse_cl_value("u32", "+1").unwrap(),
            1u32.to_bytes().unwrap()
        );
        assert_eq!(
            parse_cl_value("u64", "18446744073709551615").unwrap(),
            u64::MAX.to_bytes().unwrap()
        );
        assert_eq!(
            parse_cl_value("U128", "340282366920938463463374607431768211455").unwrap(),
            U128::from_dec_str("340282366920938463463374607431768211455")
                .unwrap()
                .to_bytes()
                .unwrap()
        );
        assert_eq!(
            parse_cl_value("U256", "1").unwrap(),
            U256::from_dec_str("1").unwrap().to_bytes().unwrap()
        );
        assert_eq!(
            parse_cl_value("U512", "2").unwrap(),
            U512::from_dec_str("2").unwrap().to_bytes().unwrap()
        );
    }

    #[test]
    fn rejects_unsigned_negative_values() {
        assert!(parse_cl_value("u8", "-1").is_err());
        assert!(parse_cl_value("u32", "-1").is_err());
        assert!(parse_cl_value("u64", "-1").is_err());
        assert!(parse_cl_value("U128", "-1").is_err());
    }

    #[test]
    fn rejects_unsigned_overflow() {
        let u8_over = format!("{}", u8::MAX as u16 + 1);
        let u64_over = format!("{}", u64::MAX as u128 + 1);
        assert!(parse_cl_value("u8", &u8_over).is_err());
        assert!(parse_cl_value("u64", &u64_over).is_err());
        assert!(parse_cl_value("U128", "340282366920938463463374607431768211456").is_err());
    }

    #[test]
    fn parses_unit() {
        assert_eq!(parse_cl_value("unit", "").unwrap(), Vec::<u8>::new(),);
        assert!(parse_cl_value("unit", "0x01").is_err());
        assert_eq!(
            parse_cl_value("option<unit>", "none").unwrap(),
            vec![OPTION_NONE_TAG]
        );
        assert_eq!(
            parse_cl_value("option<unit>", "0x01").unwrap(),
            vec![OPTION_SOME_TAG]
        );
    }

    #[test]
    fn formats_basic_cl_values() {
        let value = CLValue::from_t(true).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "true");

        let value = CLValue::from_t(1234u64).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "1234");

        let value = CLValue::from_t(()).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "()");
    }

    #[test]
    fn formats_string_values() {
        let value = CLValue::from_t("hello-world".to_string()).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "hello-world");

        let value = CLValue::from_t("hello world".to_string()).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "\"hello world\"");
    }

    #[test]
    fn formats_key_uref_public_key_values() {
        let key = Key::Hash([7u8; 32]);
        let key_expected = key.to_formatted_string();
        let value = CLValue::from_t(key).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), key_expected);

        let uref = URef::new([3u8; 32], AccessRights::READ);
        let uref_expected = uref.to_formatted_string();
        let value = CLValue::from_t(uref).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), uref_expected);

        let public_key = PublicKey::ed25519_from_bytes([1u8; 32]).unwrap();
        let public_key_expected = public_key.to_hex_string();
        let value = CLValue::from_t(public_key).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), public_key_expected);
    }

    #[test]
    fn formats_option_and_result_values() {
        let value: Option<u32> = Some(7);
        let value = CLValue::from_t(value).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "Some(7)");

        let value: Option<u32> = None;
        let value = CLValue::from_t(value).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "None");

        let value: Result<u32, u32> = Ok(5);
        let value = CLValue::from_t(value).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "Ok(5)");

        let value: Result<u32, u32> = Err(9);
        let value = CLValue::from_t(value).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "Err(9)");
    }
    #[test]
    fn formats_collections_and_tuples() {
        let value = vec![1u8, 2, 3];
        let value = CLValue::from_t(value).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "[1, 2, 3]");

        let mut map = BTreeMap::new();
        map.insert("alpha".to_string(), 1u32);
        map.insert("beta".to_string(), 2u32);
        let value = CLValue::from_t(map).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "{alpha: 1, beta: 2}");

        let value = (true, 7u32, "hi".to_string());
        let value = CLValue::from_t(value).unwrap();
        assert_eq!(cl_value_to_string(&value).unwrap(), "(true, 7, hi)");
    }

    #[test]
    fn formats_byte_array_and_any() {
        let value = CLValue::from_components(CLType::ByteArray(3), vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(cl_value_to_string(&value).unwrap(), "0x0a0b0c");

        let value = CLValue::from_components(CLType::Any, vec![0xde, 0xad]);
        assert_eq!(cl_value_to_string(&value).unwrap(), "0xdead");
    }

    type SuperComplexType = Result<Option<Vec<u32>>, BTreeMap<String, BTreeMap<String, u64>>>;

    #[test]
    fn super_complex_type() {
        let value_ok: SuperComplexType = Ok(Some(vec![1, 2, 3]));
        let value_err: SuperComplexType = Err({
            let mut map = BTreeMap::new();
            map.insert("alice".to_string(), {
                let mut inner_map: BTreeMap<String, u64> = BTreeMap::new();
                inner_map.insert("bob".to_string(), 1000u64);
                inner_map
            });
            map
        });
        let value_ok = CLValue::from_t(value_ok).unwrap();
        assert_eq!(
            cl_value_to_string(&value_ok).unwrap(),
            "Ok(Some([1, 2, 3]))"
        );

        let value_err = CLValue::from_t(value_err).unwrap();
        assert_eq!(
            cl_value_to_string(&value_err).unwrap(),
            "Err({alice: {bob: 1000}})"
        );
    }
}
