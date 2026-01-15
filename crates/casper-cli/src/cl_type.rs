use casper_types::CLType;
use thiserror::Error;

// Keep this aligned with upstream casper-types recursion limit.
pub(crate) const MAX_TYPE_NESTING: usize = 128;

pub type Result<T> = std::result::Result<T, CLTypeError>;

#[derive(Debug, Error)]
pub enum CLTypeError {
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
    #[error("byte array length must be followed by '{expected}' at position {pos}")]
    ByteArrayLengthExpected { expected: &'static str, pos: usize },
    #[error("byte array length is missing closing delimiter")]
    ByteArrayLengthMissingClosing,
    #[error("ByteArray expects a numeric length like ByteArray[32]")]
    ByteArrayExpectedNumeric,
    #[error("type nesting exceeds {max}")]
    TypeNestingExceeded { max: usize },
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
        return Err(CLTypeError::EmptyTypeString);
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
            return Err(CLTypeError::ExpectedGenericDelimiter {
                expected: pending.expected_delimiter(),
                name: pending.kind.name(),
            });
        }

        match &token.kind {
            TokenKind::Ident(ident) => {
                if let Some(pending) = pending_ctor {
                    return Err(CLTypeError::ExpectedGenericDelimiter {
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
                        return Err(CLTypeError::UnknownClType {
                            name: ident.to_string(),
                        });
                    }
                }
            }
            TokenKind::Number(_) => {
                return Err(CLTypeError::UnexpectedNumber { pos: token.pos });
            }
            TokenKind::LAngle => {
                let pending = pending_ctor
                    .take()
                    .ok_or(CLTypeError::UnexpectedDelimiter { delimiter: '<' })?;
                if pending.kind == GenericKind::ByteArray {
                    let len = parse_byte_array_len(&tokens, &mut index, TokenKind::RAngle)?;
                    push_type(&mut frames, CLType::ByteArray(len))?;
                } else {
                    push_frame(&mut frames, FrameKind::Generic(pending.kind))?;
                }
            }
            TokenKind::RAngle => {
                if pending_ctor.is_some() {
                    return Err(CLTypeError::UnexpectedDelimiter { delimiter: '>' });
                }
                close_frame(&mut frames, TokenKind::RAngle)?;
            }
            TokenKind::LBracket => {
                let pending = pending_ctor
                    .take()
                    .ok_or(CLTypeError::UnexpectedDelimiter { delimiter: '[' })?;
                if pending.kind != GenericKind::ByteArray {
                    return Err(CLTypeError::UnexpectedDelimiterAfter {
                        delimiter: '[',
                        context: pending.kind.name().to_string(),
                    });
                }
                let len = parse_byte_array_len(&tokens, &mut index, TokenKind::RBracket)?;
                push_type(&mut frames, CLType::ByteArray(len))?;
            }
            TokenKind::RBracket => {
                return Err(CLTypeError::UnexpectedDelimiter { delimiter: ']' });
            }
            TokenKind::LParen => {
                if let Some(pending) = pending_ctor {
                    return Err(CLTypeError::UnexpectedDelimiterAfter {
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
                    return Err(CLTypeError::UnexpectedDelimiter { delimiter: ')' });
                }
                close_frame(&mut frames, TokenKind::RParen)?;
            }
            TokenKind::Comma => {
                if pending_ctor.is_some() {
                    return Err(CLTypeError::UnexpectedDelimiter { delimiter: ',' });
                }
                let frame = frames.last_mut().ok_or(CLTypeError::Internal {
                    message: "missing frame",
                })?;
                if matches!(frame.kind, FrameKind::Root) {
                    return Err(CLTypeError::UnexpectedDelimiter { delimiter: ',' });
                }
                if frame.expecting_type {
                    return Err(CLTypeError::MissingTypeBeforeComma);
                }
                frame.expecting_type = true;
                frame.saw_comma = true;
            }
        }

        index += 1;
    }

    if let Some(pending) = pending_ctor {
        return Err(CLTypeError::ExpectedGenericDelimiter {
            expected: pending.expected_delimiter(),
            name: pending.kind.name(),
        });
    }

    if frames.len() != 1 {
        return Err(CLTypeError::MissingClosingDelimiter);
    }
    let mut root = frames.pop().ok_or(CLTypeError::Internal {
        message: "missing root frame",
    })?;
    if root.expecting_type {
        return Err(CLTypeError::IncompleteTypeString);
    }
    if root.args.len() != 1 {
        return Err(CLTypeError::ExpectedSingleType);
    }
    Ok(root.args.remove(0))
}

/// Convert a `CLType` into a canonical string representation.
///
/// The output is intended to round-trip with `parse_cl_type`.
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
                    return Err(CLTypeError::InvalidNumber { pos: idx });
                }
                let number = normalized
                    .parse::<u32>()
                    .map_err(|_| CLTypeError::InvalidNumber { pos: idx })?;
                TokenKind::Number(number)
            }
            _ => {
                return Err(CLTypeError::UnexpectedCharacter { ch, pos: idx });
            }
        };
        tokens.push(Token { kind, pos: idx });
    }
    Ok(tokens)
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
        return Err(CLTypeError::TypeNestingExceeded {
            max: MAX_TYPE_NESTING,
        });
    }
    frames.push(Frame::new(kind));
    Ok(())
}

fn ensure_expecting_type(frames: &[Frame]) -> Result<()> {
    let frame = frames.last().ok_or(CLTypeError::Internal {
        message: "missing frame",
    })?;
    if !frame.expecting_type {
        return Err(CLTypeError::ExpectedCommaOrClose);
    }
    Ok(())
}

fn push_type(frames: &mut [Frame], cl_type: CLType) -> Result<()> {
    let frame = frames.last_mut().ok_or(CLTypeError::Internal {
        message: "missing frame",
    })?;
    if !frame.expecting_type {
        return Err(CLTypeError::ExpectedCommaOrClose);
    }
    frame.args.push(cl_type);
    frame.expecting_type = false;
    Ok(())
}

fn close_frame(frames: &mut Vec<Frame>, token: TokenKind) -> Result<()> {
    let frame = frames.pop().ok_or(CLTypeError::Internal {
        message: "missing frame",
    })?;
    match (token, &frame.kind) {
        (TokenKind::RAngle, FrameKind::Generic(_)) => {}
        (TokenKind::RParen, FrameKind::Tuple) => {}
        (TokenKind::RAngle, FrameKind::Tuple) => {
            return Err(CLTypeError::UnexpectedDelimiter { delimiter: '>' });
        }
        (TokenKind::RParen, FrameKind::Generic(_)) => {
            return Err(CLTypeError::UnexpectedDelimiter { delimiter: ')' });
        }
        (TokenKind::RAngle, FrameKind::Root) | (TokenKind::RParen, FrameKind::Root) => {
            return Err(CLTypeError::UnexpectedClosingDelimiter);
        }
        _ => return Err(CLTypeError::UnexpectedClosingDelimiter),
    }

    if frame.expecting_type
        && !(frame.allow_trailing_comma() && frame.saw_comma && !frame.args.is_empty())
    {
        return Err(CLTypeError::MissingTypeBeforeClose);
    }

    let cl_type = match frame.kind {
        FrameKind::Root => {
            return Err(CLTypeError::Internal {
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
        return Err(CLTypeError::GenericArgCount {
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
        GenericKind::ByteArray => return Err(CLTypeError::ByteArrayExpectedNumeric),
    };
    Ok(cl_type)
}

fn build_tuple(frame: Frame) -> Result<CLType> {
    if frame.args.is_empty() {
        return Err(CLTypeError::TupleEmpty);
    }
    if frame.args.len() == 1 && !frame.saw_comma {
        return Err(CLTypeError::TupleCommaRequired);
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
        _ => return Err(CLTypeError::TupleArity),
    };
    Ok(cl_type)
}

fn parse_byte_array_len(tokens: &[Token], index: &mut usize, closing: TokenKind) -> Result<u32> {
    let number = match tokens.get(*index + 1) {
        Some(Token {
            kind: TokenKind::Number(value),
            ..
        }) => *value,
        Some(token) => return Err(CLTypeError::ByteArrayLengthMissingAt { pos: token.pos }),
        None => return Err(CLTypeError::ByteArrayLengthMissing),
    };
    match tokens.get(*index + 2) {
        Some(Token { kind, .. }) if *kind == closing => {}
        Some(token) => {
            let expected = match closing {
                TokenKind::RBracket => "]",
                TokenKind::RAngle => ">",
                _ => "closing delimiter",
            };
            return Err(CLTypeError::ByteArrayLengthExpected {
                expected,
                pos: token.pos,
            });
        }
        None => return Err(CLTypeError::ByteArrayLengthMissingClosing),
    }
    *index += 2;
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::{cl_type_to_string, parse_cl_type};
    use casper_types::CLType;
    use proptest::prelude::*;

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
                    .prop_map(|(t1, t2)| CLType::Tuple2([Box::new(t1), Box::new(t2)])),
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
}
