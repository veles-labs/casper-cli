use casper_types::bytesrepr::{
    FromBytes, OPTION_NONE_TAG, OPTION_SOME_TAG, RESULT_ERR_TAG, RESULT_OK_TAG, ToBytes,
};
use casper_types::crypto::AsymmetricType;
use casper_types::{CLType, CLValue, Key, PublicKey, U128, U256, U512, URef};
use thiserror::Error;

type Result<T> = std::result::Result<T, ArgumentsError>;

#[derive(Debug, Error)]
pub enum ArgumentsError {
    #[error("type string is empty")]
    EmptyTypeString,
    #[error("expected {expected} after {name}")]
    ExpectedGenericDelimiter {
        expected: &'static str,
        name: &'static str,
    },
    #[error("unknown CLType '{name}'")]
    UnknownClType { name: String },
    #[error("unexpected number at position {pos}")]
    UnexpectedNumber { pos: usize },
    #[error("invalid number at position {pos}")]
    InvalidNumber { pos: usize },
    #[error("unexpected character '{ch}' at position {pos}")]
    UnexpectedCharacter { ch: char, pos: usize },
    #[error("unexpected delimiter '{delimiter}'")]
    UnexpectedDelimiter { delimiter: char },
    #[error("unexpected delimiter '{delimiter}' after {context}")]
    UnexpectedDelimiterAfter { delimiter: char, context: String },
    #[error("unexpected closing delimiter")]
    UnexpectedClosingDelimiter,
    #[error("missing type before ','")]
    MissingTypeBeforeComma,
    #[error("missing type before closing delimiter")]
    MissingTypeBeforeClose,
    #[error("missing closing delimiter")]
    MissingClosingDelimiter,
    #[error("type string is incomplete")]
    IncompleteTypeString,
    #[error("expected a single type")]
    ExpectedSingleType,
    #[error("expected ',' or closing delimiter")]
    ExpectedCommaOrClose,
    #[error("{name} expects {expected} type argument(s)")]
    GenericArgCount {
        name: &'static str,
        expected: usize,
        found: usize,
    },
    #[error("tuple types cannot be empty")]
    TupleEmpty,
    #[error("tuple types require a comma, use '(T,)'")]
    TupleCommaRequired,
    #[error("tuple types support 1, 2, or 3 elements")]
    TupleArity,
    #[error("byte array length is missing")]
    ByteArrayLengthMissing,
    #[error("byte array length is missing at position {pos}")]
    ByteArrayLengthMissingAt { pos: usize },
    #[error("byte array length is too large")]
    ByteArrayLengthTooLarge,
    #[error("byte array length must be followed by '{expected}' at position {pos}")]
    ByteArrayLengthExpected { expected: &'static str, pos: usize },
    #[error("byte array length is missing closing delimiter")]
    ByteArrayLengthMissingClosing,
    #[error("ByteArray expects a numeric length like ByteArray[32]")]
    ByteArrayExpectedNumeric,
    #[error("type nesting exceeds {max}")]
    TypeNestingExceeded { max: usize },
    #[error("value has trailing bytes")]
    ValueTrailingBytes,
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
    #[error("internal parser error: {message}")]
    Internal { message: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Number(u32),
    LAngle,
    RAngle,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenericKind {
    Option,
    List,
    Result,
    Map,
    Tuple1,
    Tuple2,
    Tuple3,
    ByteArray,
}

impl GenericKind {
    fn name(self) -> &'static str {
        match self {
            GenericKind::Option => "Option",
            GenericKind::List => "List",
            GenericKind::Result => "Result",
            GenericKind::Map => "Map",
            GenericKind::Tuple1 => "Tuple1",
            GenericKind::Tuple2 => "Tuple2",
            GenericKind::Tuple3 => "Tuple3",
            GenericKind::ByteArray => "ByteArray",
        }
    }

    fn expected_args(self) -> usize {
        match self {
            GenericKind::Option => 1,
            GenericKind::List => 1,
            GenericKind::Result => 2,
            GenericKind::Map => 2,
            GenericKind::Tuple1 => 1,
            GenericKind::Tuple2 => 2,
            GenericKind::Tuple3 => 3,
            GenericKind::ByteArray => 1,
        }
    }
}

#[derive(Debug)]
enum FrameKind {
    Root,
    Generic(GenericKind),
    Tuple,
}

#[derive(Debug)]
struct Frame {
    kind: FrameKind,
    args: Vec<CLType>,
    expecting_type: bool,
    saw_comma: bool,
}

impl Frame {
    fn new(kind: FrameKind) -> Self {
        Self {
            kind,
            args: Vec::new(),
            expecting_type: true,
            saw_comma: false,
        }
    }

    fn allow_trailing_comma(&self) -> bool {
        matches!(self.kind, FrameKind::Tuple)
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingCtor {
    kind: GenericKind,
}

impl PendingCtor {
    fn expected_delimiter(self) -> &'static str {
        match self.kind {
            GenericKind::ByteArray => "'[' or '<'",
            _ => "'<'",
        }
    }
}

// Keep this aligned with upstream casper-types recursion limit.
const MAX_TYPE_NESTING: usize = 128;

/// Parse a `CLType` from a string representation.
///
/// Accepted CLType syntax (case-insensitive, `_` and `-` ignored in identifiers):
/// - Primitives: `Bool`, `I32`, `I64`, `U8`, `U32`, `U64`, `U128`, `U256`, `U512`, `Unit`,
///   `String`, `Key`, `URef`, `PublicKey`, `Any`
/// - Generics: `Option<T>`, `List<T>`, `Result<Ok, Err>`, `Map<K, V>`
/// - Tuples: `(T,)`, `(T, U)`, `(T, U, V)`
/// - Byte array: `ByteArray[32]` or `ByteArray<32>` (underscores allowed in the length)
/// - Aliases: `account_hash`/`account-hash` => `ByteArray[32]`,
///   `byte_array`/`byte-array` => `ByteArray[...]`,
///   `public_key`/`public-key` => `PublicKey`
///
/// Nesting is limited to `MAX_TYPE_NESTING` to match upstream constraints.
///
/// Compared to the `casper-client` argument format (e.g. `opt_i32`, `opt_string`),
/// this parser accepts full CLType syntax, supports nesting, and includes generic
/// types such as `Result`, `List`, and `Map`.
pub fn parse_cl_type(value: &str) -> Result<CLType> {
    let normalized: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    if normalized == "()" {
        return Ok(CLType::Unit);
    }
    let tokens = tokenize(value)?;
    if tokens.is_empty() {
        return Err(ArgumentsError::EmptyTypeString);
    }

    let mut frames = vec![Frame::new(FrameKind::Root)];
    let mut pending_ctor: Option<PendingCtor> = None;
    let mut index = 0usize;

    while index < tokens.len() {
        let token = &tokens[index];
        // Once a generic name is seen, require an opening delimiter next.
        if let Some(pending) = pending_ctor
            && !matches!(token.kind, TokenKind::LAngle | TokenKind::LBracket)
        {
            return Err(ArgumentsError::ExpectedGenericDelimiter {
                expected: pending.expected_delimiter(),
                name: pending.kind.name(),
            });
        }

        match &token.kind {
            TokenKind::Ident(ident) => {
                if let Some(pending) = pending_ctor {
                    return Err(ArgumentsError::ExpectedGenericDelimiter {
                        expected: pending.expected_delimiter(),
                        name: pending.kind.name(),
                    });
                }
                let normalized = normalize_ident(ident);
                match normalized.as_str() {
                    "accounthash" => push_type(&mut frames, CLType::ByteArray(32))?,
                    "option" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::Option,
                        });
                    }
                    "list" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::List,
                        });
                    }
                    "result" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::Result,
                        });
                    }
                    "map" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::Map,
                        });
                    }
                    "tuple1" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::Tuple1,
                        });
                    }
                    "tuple2" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::Tuple2,
                        });
                    }
                    "tuple3" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::Tuple3,
                        });
                    }
                    "bytearray" => {
                        ensure_expecting_type(&frames)?;
                        pending_ctor = Some(PendingCtor {
                            kind: GenericKind::ByteArray,
                        });
                    }
                    "bool" => push_type(&mut frames, CLType::Bool)?,
                    "i32" => push_type(&mut frames, CLType::I32)?,
                    "i64" => push_type(&mut frames, CLType::I64)?,
                    "u8" => push_type(&mut frames, CLType::U8)?,
                    "u32" => push_type(&mut frames, CLType::U32)?,
                    "u64" => push_type(&mut frames, CLType::U64)?,
                    "u128" => push_type(&mut frames, CLType::U128)?,
                    "u256" => push_type(&mut frames, CLType::U256)?,
                    "u512" => push_type(&mut frames, CLType::U512)?,
                    "unit" => push_type(&mut frames, CLType::Unit)?,
                    "string" => push_type(&mut frames, CLType::String)?,
                    "key" => push_type(&mut frames, CLType::Key)?,
                    "uref" => push_type(&mut frames, CLType::URef)?,
                    "publickey" => push_type(&mut frames, CLType::PublicKey)?,
                    "any" => push_type(&mut frames, CLType::Any)?,
                    _ => {
                        return Err(ArgumentsError::UnknownClType {
                            name: ident.to_string(),
                        });
                    }
                }
            }
            TokenKind::Number(_) => {
                return Err(ArgumentsError::UnexpectedNumber { pos: token.pos });
            }
            TokenKind::LAngle => {
                let pending = pending_ctor
                    .take()
                    .ok_or(ArgumentsError::UnexpectedDelimiter { delimiter: '<' })?;
                if pending.kind == GenericKind::ByteArray {
                    let len = parse_byte_array_len(&tokens, &mut index, TokenKind::RAngle)?;
                    push_type(&mut frames, CLType::ByteArray(len))?;
                } else {
                    push_frame(&mut frames, FrameKind::Generic(pending.kind))?;
                }
            }
            TokenKind::RAngle => {
                if pending_ctor.is_some() {
                    return Err(ArgumentsError::UnexpectedDelimiter { delimiter: '>' });
                }
                close_frame(&mut frames, TokenKind::RAngle)?;
            }
            TokenKind::LBracket => {
                let pending = pending_ctor
                    .take()
                    .ok_or(ArgumentsError::UnexpectedDelimiter { delimiter: '[' })?;
                if pending.kind != GenericKind::ByteArray {
                    return Err(ArgumentsError::UnexpectedDelimiterAfter {
                        delimiter: '[',
                        context: pending.kind.name().to_string(),
                    });
                }
                let len = parse_byte_array_len(&tokens, &mut index, TokenKind::RBracket)?;
                push_type(&mut frames, CLType::ByteArray(len))?;
            }
            TokenKind::RBracket => {
                return Err(ArgumentsError::UnexpectedDelimiter { delimiter: ']' });
            }
            TokenKind::LParen => {
                if let Some(pending) = pending_ctor {
                    return Err(ArgumentsError::UnexpectedDelimiterAfter {
                        delimiter: '(',
                        context: pending.kind.name().to_string(),
                    });
                }
                if matches!(
                    tokens.get(index + 1),
                    Some(Token {
                        kind: TokenKind::RParen,
                        ..
                    })
                ) {
                    ensure_expecting_type(&frames)?;
                    push_type(&mut frames, CLType::Unit)?;
                    index += 1;
                } else {
                    ensure_expecting_type(&frames)?;
                    push_frame(&mut frames, FrameKind::Tuple)?;
                }
            }
            TokenKind::RParen => {
                if pending_ctor.is_some() {
                    return Err(ArgumentsError::UnexpectedDelimiter { delimiter: ')' });
                }
                close_frame(&mut frames, TokenKind::RParen)?;
            }
            TokenKind::Comma => {
                if pending_ctor.is_some() {
                    return Err(ArgumentsError::UnexpectedDelimiter { delimiter: ',' });
                }
                let frame = frames.last_mut().ok_or(ArgumentsError::Internal {
                    message: "missing frame",
                })?;
                if matches!(frame.kind, FrameKind::Root) {
                    return Err(ArgumentsError::UnexpectedDelimiter { delimiter: ',' });
                }
                if frame.expecting_type {
                    return Err(ArgumentsError::MissingTypeBeforeComma);
                }
                frame.expecting_type = true;
                frame.saw_comma = true;
            }
        }

        index += 1;
    }

    if let Some(pending) = pending_ctor {
        return Err(ArgumentsError::ExpectedGenericDelimiter {
            expected: pending.expected_delimiter(),
            name: pending.kind.name(),
        });
    }

    if frames.len() != 1 {
        return Err(ArgumentsError::MissingClosingDelimiter);
    }
    let mut root = frames.pop().ok_or(ArgumentsError::Internal {
        message: "missing root frame",
    })?;
    if root.expecting_type {
        return Err(ArgumentsError::IncompleteTypeString);
    }
    if root.args.len() != 1 {
        return Err(ArgumentsError::ExpectedSingleType);
    }
    Ok(root.args.remove(0))
}

/// Convert a `CLType` into a canonical string representation.
///
/// The output is intended to round-trip with `parse_cl_type`.
#[cfg(test)]
pub fn cl_type_to_string(cl_type: &CLType) -> String {
    match cl_type {
        CLType::Bool => "Bool".to_string(),
        CLType::I32 => "I32".to_string(),
        CLType::I64 => "I64".to_string(),
        CLType::U8 => "U8".to_string(),
        CLType::U32 => "U32".to_string(),
        CLType::U64 => "U64".to_string(),
        CLType::U128 => "U128".to_string(),
        CLType::U256 => "U256".to_string(),
        CLType::U512 => "U512".to_string(),
        CLType::Unit => "Unit".to_string(),
        CLType::String => "String".to_string(),
        CLType::Key => "Key".to_string(),
        CLType::URef => "URef".to_string(),
        CLType::PublicKey => "PublicKey".to_string(),
        CLType::Option(inner) => format!("Option<{}>", cl_type_to_string(inner)),
        CLType::List(inner) => format!("List<{}>", cl_type_to_string(inner)),
        CLType::ByteArray(len) => format!("ByteArray[{len}]"),
        CLType::Result { ok, err } => format!(
            "Result<{}, {}>",
            cl_type_to_string(ok),
            cl_type_to_string(err)
        ),
        CLType::Map { key, value } => format!(
            "Map<{}, {}>",
            cl_type_to_string(key),
            cl_type_to_string(value)
        ),
        CLType::Tuple1([t1]) => format!("({},)", cl_type_to_string(t1)),
        CLType::Tuple2([t1, t2]) => {
            format!("({}, {})", cl_type_to_string(t1), cl_type_to_string(t2))
        }
        CLType::Tuple3([t1, t2, t3]) => format!(
            "({}, {}, {})",
            cl_type_to_string(t1),
            cl_type_to_string(t2),
            cl_type_to_string(t3)
        ),
        CLType::Any => "Any".to_string(),
    }
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
            return Err(ArgumentsError::ValueTrailingBytes);
        }
        Ok(bytes)
    } else {
        parse_basic_value(&cl_type, input)
    }
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

fn tokenize(value: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = value.char_indices().peekable();
    while let Some((idx, ch)) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        let kind = match ch {
            '<' => {
                chars.next();
                TokenKind::LAngle
            }
            '>' => {
                chars.next();
                TokenKind::RAngle
            }
            '[' => {
                chars.next();
                TokenKind::LBracket
            }
            ']' => {
                chars.next();
                TokenKind::RBracket
            }
            '(' => {
                chars.next();
                TokenKind::LParen
            }
            ')' => {
                chars.next();
                TokenKind::RParen
            }
            ',' => {
                chars.next();
                TokenKind::Comma
            }
            _ if ch.is_ascii_alphabetic() => {
                let mut ident = String::new();
                while let Some((_, next)) = chars.peek().copied() {
                    if next.is_ascii_alphanumeric() || next == '-' || next == '_' {
                        ident.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                TokenKind::Ident(ident)
            }
            _ if ch.is_ascii_digit() => {
                let mut digits = String::new();
                while let Some((_, next)) = chars.peek().copied() {
                    if next.is_ascii_digit() || next == '_' {
                        digits.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let normalized: String = digits.chars().filter(|c| *c != '_').collect();
                if normalized.is_empty() {
                    return Err(ArgumentsError::InvalidNumber { pos: idx });
                }
                let number = normalized
                    .parse::<u32>()
                    .map_err(|_| ArgumentsError::InvalidNumber { pos: idx })?;
                TokenKind::Number(number)
            }
            _ => {
                return Err(ArgumentsError::UnexpectedCharacter { ch, pos: idx });
            }
        };
        tokens.push(Token { kind, pos: idx });
    }
    Ok(tokens)
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

fn normalize_ident(ident: &str) -> String {
    ident
        .chars()
        .filter(|ch| *ch != '-' && *ch != '_')
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn push_frame(frames: &mut Vec<Frame>, kind: FrameKind) -> Result<()> {
    if frames.len() > MAX_TYPE_NESTING {
        return Err(ArgumentsError::TypeNestingExceeded {
            max: MAX_TYPE_NESTING,
        });
    }
    frames.push(Frame::new(kind));
    Ok(())
}

fn to_bytes_label<T: ToBytes>(value: &T, label: &'static str) -> Result<Vec<u8>> {
    value
        .to_bytes()
        .map_err(|err| ArgumentsError::InvalidBytes {
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
                Err(ArgumentsError::InvalidUnitValue)
            }
        }
        CLType::String => to_bytes_label(&input.to_string(), "string"),
        CLType::Key => {
            let trimmed = input.trim();
            let value =
                Key::from_formatted_str(trimmed).map_err(|err| ArgumentsError::InvalidKey {
                    message: err.to_string(),
                })?;
            to_bytes_label(&value, "key")
        }
        CLType::URef => {
            let trimmed = input.trim();
            let value =
                URef::from_formatted_str(trimmed).map_err(|err| ArgumentsError::InvalidURef {
                    message: err.to_string(),
                })?;
            to_bytes_label(&value, "uref")
        }
        CLType::PublicKey => {
            let hex = normalize_hex_input(input);
            let value = PublicKey::from_hex(hex.as_bytes()).map_err(|err| {
                ArgumentsError::InvalidPublicKey {
                    message: err.to_string(),
                }
            })?;
            to_bytes_label(&value, "public-key")
        }
        CLType::Any => Err(ArgumentsError::AnyRequiresHex),
        _ => Err(ArgumentsError::TypeRequiresHex),
    }
}

fn parse_bool(input: &str) -> Result<bool> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ArgumentsError::InvalidBool),
    }
}

fn parse_i32(input: &str) -> Result<i32> {
    let normalized = normalize_decimal(input)?;
    normalized
        .parse::<i32>()
        .map_err(|_| ArgumentsError::InvalidI32)
}

fn parse_i64(input: &str) -> Result<i64> {
    let normalized = normalize_decimal(input)?;
    normalized
        .parse::<i64>()
        .map_err(|_| ArgumentsError::InvalidI64)
}

fn parse_u8(input: &str) -> Result<u8> {
    let normalized = normalize_unsigned_decimal(input)?;
    normalized
        .parse::<u8>()
        .map_err(|_| ArgumentsError::InvalidU8)
}

fn parse_u32(input: &str) -> Result<u32> {
    let normalized = normalize_unsigned_decimal(input)?;
    normalized
        .parse::<u32>()
        .map_err(|_| ArgumentsError::InvalidU32)
}

fn parse_u64(input: &str) -> Result<u64> {
    let normalized = normalize_unsigned_decimal(input)?;
    normalized
        .parse::<u64>()
        .map_err(|_| ArgumentsError::InvalidU64)
}

fn parse_u128(input: &str) -> Result<U128> {
    let normalized = normalize_unsigned_decimal(input)?;
    U128::from_dec_str(&normalized).map_err(|_| ArgumentsError::InvalidU128)
}

fn parse_u256(input: &str) -> Result<U256> {
    let normalized = normalize_unsigned_decimal(input)?;
    U256::from_dec_str(&normalized).map_err(|_| ArgumentsError::InvalidU256)
}

fn parse_u512(input: &str) -> Result<U512> {
    let normalized = normalize_unsigned_decimal(input)?;
    U512::from_dec_str(&normalized).map_err(|_| ArgumentsError::InvalidU512)
}

fn normalize_decimal(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ArgumentsError::EmptyValue);
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
            return Err(ArgumentsError::InvalidDecimalDigit { ch });
        }
    }
    if normalized == "-" || normalized == "+" {
        return Err(ArgumentsError::MissingDigits);
    }
    Ok(normalized)
}

fn normalize_unsigned_decimal(input: &str) -> Result<String> {
    let normalized = normalize_decimal(input)?;
    if normalized.starts_with('-') {
        return Err(ArgumentsError::UnsignedNegative);
    }
    Ok(normalized.trim_start_matches('+').to_string())
}

fn parse_hex_input(input: &str) -> Result<Vec<u8>> {
    let normalized = normalize_hex_input(input);
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    if normalized.len() % 2 != 0 {
        return Err(ArgumentsError::OddHexLength);
    }
    hex::decode(&normalized).map_err(|err| ArgumentsError::InvalidHex {
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
            return Err(ArgumentsError::ValueTooShort);
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
                        _ => return Err(ArgumentsError::InvalidOptionTag),
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
                        .map_err(|_| ArgumentsError::ByteArrayLengthTooLarge)?;
                    cursor.take(len)?;
                }
                CLType::Result { ok, err } => {
                    let tag = cursor.take_u8()?;
                    match tag {
                        RESULT_ERR_TAG => stack.push(ValueTask::Type(err.as_ref())),
                        RESULT_OK_TAG => stack.push(ValueTask::Type(ok.as_ref())),
                        _ => return Err(ArgumentsError::InvalidResultTag),
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
                CLType::Any => return Err(ArgumentsError::AnyNotSupported),
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

fn consume_from_bytes<T: FromBytes>(
    cursor: &mut ValueCursor<'_>,
    label: &'static str,
) -> Result<()> {
    let remaining = cursor.remaining_slice();
    let (_value, remainder) =
        T::from_bytes(remaining).map_err(|err| ArgumentsError::InvalidBytes {
            label,
            message: err.to_string(),
        })?;
    let consumed =
        remaining
            .len()
            .checked_sub(remainder.len())
            .ok_or(ArgumentsError::Internal {
                message: "invalid remainder length",
            })?;
    cursor.pos = cursor
        .pos
        .checked_add(consumed)
        .ok_or(ArgumentsError::ValueLengthOverflow)?;
    Ok(())
}

fn ensure_expecting_type(frames: &[Frame]) -> Result<()> {
    let frame = frames.last().ok_or(ArgumentsError::Internal {
        message: "missing frame",
    })?;
    if !frame.expecting_type {
        return Err(ArgumentsError::ExpectedCommaOrClose);
    }
    Ok(())
}

fn push_type(frames: &mut [Frame], cl_type: CLType) -> Result<()> {
    let frame = frames.last_mut().ok_or(ArgumentsError::Internal {
        message: "missing frame",
    })?;
    if !frame.expecting_type {
        return Err(ArgumentsError::ExpectedCommaOrClose);
    }
    frame.args.push(cl_type);
    frame.expecting_type = false;
    Ok(())
}

fn close_frame(frames: &mut Vec<Frame>, token: TokenKind) -> Result<()> {
    let frame = frames.pop().ok_or(ArgumentsError::Internal {
        message: "missing frame",
    })?;
    match (token, &frame.kind) {
        (TokenKind::RAngle, FrameKind::Generic(_)) => {}
        (TokenKind::RParen, FrameKind::Tuple) => {}
        (TokenKind::RAngle, FrameKind::Tuple) => {
            return Err(ArgumentsError::UnexpectedDelimiter { delimiter: '>' });
        }
        (TokenKind::RParen, FrameKind::Generic(_)) => {
            return Err(ArgumentsError::UnexpectedDelimiter { delimiter: ')' });
        }
        (TokenKind::RAngle, FrameKind::Root) | (TokenKind::RParen, FrameKind::Root) => {
            return Err(ArgumentsError::UnexpectedClosingDelimiter);
        }
        _ => return Err(ArgumentsError::UnexpectedClosingDelimiter),
    }

    if frame.expecting_type
        && !(frame.allow_trailing_comma() && frame.saw_comma && !frame.args.is_empty())
    {
        return Err(ArgumentsError::MissingTypeBeforeClose);
    }

    let cl_type = match frame.kind {
        FrameKind::Root => {
            return Err(ArgumentsError::Internal {
                message: "unexpected root frame",
            });
        }
        FrameKind::Tuple => build_tuple(frame)?,
        FrameKind::Generic(kind) => build_generic(kind, frame.args)?,
    };

    push_type(frames, cl_type)
}

fn build_generic(kind: GenericKind, args: Vec<CLType>) -> Result<CLType> {
    let expected = kind.expected_args();
    if args.len() != expected {
        return Err(ArgumentsError::GenericArgCount {
            name: kind.name(),
            expected,
            found: args.len(),
        });
    }
    let mut iter = args.into_iter();
    let cl_type = match kind {
        GenericKind::Option => CLType::Option(Box::new(iter.next().unwrap())),
        GenericKind::List => CLType::List(Box::new(iter.next().unwrap())),
        GenericKind::Result => CLType::Result {
            ok: Box::new(iter.next().unwrap()),
            err: Box::new(iter.next().unwrap()),
        },
        GenericKind::Map => CLType::Map {
            key: Box::new(iter.next().unwrap()),
            value: Box::new(iter.next().unwrap()),
        },
        GenericKind::Tuple1 => CLType::Tuple1([Box::new(iter.next().unwrap())]),
        GenericKind::Tuple2 => CLType::Tuple2([
            Box::new(iter.next().unwrap()),
            Box::new(iter.next().unwrap()),
        ]),
        GenericKind::Tuple3 => CLType::Tuple3([
            Box::new(iter.next().unwrap()),
            Box::new(iter.next().unwrap()),
            Box::new(iter.next().unwrap()),
        ]),
        GenericKind::ByteArray => return Err(ArgumentsError::ByteArrayExpectedNumeric),
    };
    Ok(cl_type)
}

fn build_tuple(frame: Frame) -> Result<CLType> {
    if frame.args.is_empty() {
        return Err(ArgumentsError::TupleEmpty);
    }
    if frame.args.len() == 1 && !frame.saw_comma {
        return Err(ArgumentsError::TupleCommaRequired);
    }
    let len = frame.args.len();
    let mut iter = frame.args.into_iter();
    let cl_type = match len {
        1 => CLType::Tuple1([Box::new(iter.next().unwrap())]),
        2 => CLType::Tuple2([
            Box::new(iter.next().unwrap()),
            Box::new(iter.next().unwrap()),
        ]),
        3 => CLType::Tuple3([
            Box::new(iter.next().unwrap()),
            Box::new(iter.next().unwrap()),
            Box::new(iter.next().unwrap()),
        ]),
        _ => return Err(ArgumentsError::TupleArity),
    };
    Ok(cl_type)
}

fn parse_byte_array_len(tokens: &[Token], index: &mut usize, closing: TokenKind) -> Result<u32> {
    let number = match tokens.get(*index + 1) {
        Some(Token {
            kind: TokenKind::Number(value),
            ..
        }) => *value,
        Some(token) => return Err(ArgumentsError::ByteArrayLengthMissingAt { pos: token.pos }),
        None => return Err(ArgumentsError::ByteArrayLengthMissing),
    };
    match tokens.get(*index + 2) {
        Some(Token { kind, .. }) if *kind == closing => {}
        Some(token) => {
            let expected = match closing {
                TokenKind::RBracket => "]",
                TokenKind::RAngle => ">",
                _ => "closing delimiter",
            };
            return Err(ArgumentsError::ByteArrayLengthExpected {
                expected,
                pos: token.pos,
            });
        }
        None => return Err(ArgumentsError::ByteArrayLengthMissingClosing),
    }
    *index += 2;
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::{cl_type_to_string, parse_argument, parse_cl_type, parse_cl_value};
    use casper_types::bytesrepr::{
        OPTION_NONE_TAG, OPTION_SOME_TAG, RESULT_ERR_TAG, RESULT_OK_TAG, ToBytes,
    };
    use casper_types::crypto::AsymmetricType;
    use casper_types::{AccessRights, CLType, CLValue, Key, PublicKey, U128, U256, U512, URef};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn cl_type_strategy() -> impl Strategy<Value = CLType> {
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
            (0u32..=64).prop_map(CLType::ByteArray),
            Just(CLType::Any),
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
                    .prop_map(|(t1, t2)| CLType::Tuple2([Box::new(t1), Box::new(t2),])),
                (inner.clone(), inner.clone(), inner.clone()).prop_map(|(t1, t2, t3)| {
                    CLType::Tuple3([Box::new(t1), Box::new(t2), Box::new(t3)])
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn roundtrip_cl_type_string(cl_type in cl_type_strategy()) {
            let text = cl_type_to_string(&cl_type);
            let parsed = parse_cl_type(&text).unwrap();
            prop_assert_eq!(parsed, cl_type);
        }
    }

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
                    .prop_map(|(t1, t2)| CLType::Tuple2([Box::new(t1), Box::new(t2),])),
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
    fn parses_basic_types() {
        assert_eq!(parse_cl_type("Bool").unwrap(), CLType::Bool);
        assert_eq!(parse_cl_type("string").unwrap(), CLType::String);
        assert_eq!(parse_cl_type("URef").unwrap(), CLType::URef);
    }

    #[test]
    fn parses_unit_alias() {
        assert_eq!(parse_cl_type("()").unwrap(), CLType::Unit);
        assert_eq!(parse_cl_type(" ( ) ").unwrap(), CLType::Unit);
        assert_eq!(
            parse_cl_type("Option<()>").unwrap(),
            CLType::Option(Box::new(CLType::Unit))
        );
        assert_eq!(
            parse_cl_type("Option<Option<()>>").unwrap(),
            CLType::Option(Box::new(CLType::Option(Box::new(CLType::Unit))))
        );
    }

    #[test]
    fn parses_system_cl_types() {
        assert_eq!(parse_cl_type("Key").unwrap(), CLType::Key);
        assert_eq!(parse_cl_type("uref").unwrap(), CLType::URef);
        assert_eq!(parse_cl_type("public-key").unwrap(), CLType::PublicKey);
        assert_eq!(parse_cl_type("Any").unwrap(), CLType::Any);
    }

    #[test]
    fn parses_cl_type_aliases() {
        assert_eq!(
            parse_cl_type("account_hash").unwrap(),
            CLType::ByteArray(32)
        );
        assert_eq!(
            parse_cl_type("Option<AccountHash>").unwrap(),
            CLType::Option(Box::new(CLType::ByteArray(32)))
        );
        assert_eq!(
            parse_cl_type("Option<Option<AccountHash>>").unwrap(),
            CLType::Option(Box::new(CLType::Option(Box::new(CLType::ByteArray(32)))))
        );
        assert_eq!(
            parse_cl_type("byte_array[4]").unwrap(),
            CLType::ByteArray(4)
        );
        assert_eq!(
            parse_cl_type("Option<ByteArray[4]>").unwrap(),
            CLType::Option(Box::new(CLType::ByteArray(4)))
        );
        assert_eq!(
            parse_cl_type("Option<Option<ByteArray[4]>>").unwrap(),
            CLType::Option(Box::new(CLType::Option(Box::new(CLType::ByteArray(4)))))
        );

        assert_eq!(parse_cl_type("public_key").unwrap(), CLType::PublicKey);
    }

    #[test]
    fn parses_nested_option_result() {
        let parsed = parse_cl_type("Result<Option<U64>, U64>").unwrap();
        assert_eq!(
            parsed,
            CLType::Result {
                ok: Box::new(CLType::Option(Box::new(CLType::U64))),
                err: Box::new(CLType::U64),
            }
        );
    }

    #[test]
    fn parses_byte_array() {
        assert_eq!(
            parse_cl_type("ByteArray[32]").unwrap(),
            CLType::ByteArray(32)
        );
        assert_eq!(
            parse_cl_type("bytearray[1_024]").unwrap(),
            CLType::ByteArray(1024)
        );
    }

    #[test]
    fn parses_tuple_syntax() {
        assert_eq!(
            parse_cl_type("(Bool,)").unwrap(),
            CLType::Tuple1([Box::new(CLType::Bool)])
        );
        assert_eq!(
            parse_cl_type("(Bool, String)").unwrap(),
            CLType::Tuple2([Box::new(CLType::Bool), Box::new(CLType::String)])
        );
        assert_eq!(
            parse_cl_type("(Bool, String, U8)").unwrap(),
            CLType::Tuple3([
                Box::new(CLType::Bool),
                Box::new(CLType::String),
                Box::new(CLType::U8),
            ])
        );
        assert_eq!(
            parse_cl_type("(ByteArray[32], Option<Bool>, U8)").unwrap(),
            CLType::Tuple3([
                Box::new(CLType::ByteArray(32)),
                Box::new(CLType::Option(Box::new(CLType::Bool))),
                Box::new(CLType::U8),
            ])
        );
    }

    #[test]
    fn rejects_empty_generics() {
        assert!(parse_cl_type("Bool<>").is_err());
        assert!(parse_cl_type("Option<>").is_err());
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
        for _ in 0..=super::MAX_TYPE_NESTING {
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
}
