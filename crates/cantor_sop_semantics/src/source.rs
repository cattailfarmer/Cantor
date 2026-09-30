//! Bounded SOP authoring grammar with exact source ranges and tolerant analysis.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::*;

pub const SOURCE_PROFILE: &str = "cantor-sop-semantic-source/0.1";
pub const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DIAGNOSTICS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    pub start: u64,
    pub end: u64,
}

impl Diagnostic {
    fn new(code: &str, message: impl Into<String>, start: usize, end: usize) -> Self {
        let mut message = message.into();
        if message.len() > 4096 {
            let mut boundary = 4096;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
            message.push('…');
        }
        Self {
            code: code.to_owned(),
            message,
            start: start as u64,
            end: end as u64,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declarations {
    pub kinds: Vec<Kind>,
    pub contexts: Vec<Context>,
    pub units: Vec<Unit>,
    pub relation_types: Vec<RelationType>,
    pub relations: Vec<Relation>,
    pub rules: Vec<Rule>,
    pub views: Vec<View>,
}

impl Declarations {
    pub fn append_to(self, input: &mut SnapshotInput) {
        input.kinds.extend(self.kinds);
        input.contexts.extend(self.contexts);
        input.units.extend(self.units);
        input.relation_types.extend(self.relation_types);
        input.relations.extend(self.relations);
        input.rules.extend(self.rules);
        input.views.extend(self.views);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentAnalysis {
    pub profile: String,
    pub declarations: Declarations,
    pub diagnostics: Vec<Diagnostic>,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    Id(String),
    Text(String),
    Open,
    Close,
    Left,
    Right,
    Comma,
    Range,
    Comment,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

fn lex(text: &str) -> (Vec<Token>, Option<Diagnostic>) {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = if text.starts_with('\u{feff}') { 3 } else { 0 };
    while index < bytes.len() {
        let start = index;
        let kind = match bytes[index] {
            b' ' | b'\t' | b'\r' | b'\n' | b';' => {
                index += 1;
                continue;
            }
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                TokenKind::Comment
            }
            b'{' => {
                index += 1;
                TokenKind::Open
            }
            b'}' => {
                index += 1;
                TokenKind::Close
            }
            b'(' => {
                index += 1;
                TokenKind::Left
            }
            b')' => {
                index += 1;
                TokenKind::Right
            }
            b',' => {
                index += 1;
                TokenKind::Comma
            }
            b'.' if bytes.get(index + 1) == Some(&b'.') => {
                index += 2;
                TokenKind::Range
            }
            b'[' => {
                index += 1;
                let content = index;
                while index < bytes.len()
                    && bytes[index] != b']'
                    && bytes[index] != b'\n'
                    && bytes[index] != b'\r'
                {
                    index += 1;
                }
                if bytes.get(index) != Some(&b']') {
                    return (
                        tokens,
                        Some(Diagnostic::new(
                            "incomplete_reference",
                            "close the bracketed identifier with ]",
                            start,
                            index,
                        )),
                    );
                }
                let id = text[content..index].to_owned();
                index += 1;
                TokenKind::Id(id)
            }
            b'"' => {
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == b'"' {
                        index += 1;
                        closed = true;
                        break;
                    } else {
                        index += 1;
                    }
                }
                if !closed {
                    return (
                        tokens,
                        Some(Diagnostic::new(
                            "incomplete_string",
                            "close the quoted string",
                            start,
                            bytes.len(),
                        )),
                    );
                }
                match serde_json::from_str::<String>(&text[start..index]) {
                    Ok(value) => TokenKind::Text(value),
                    Err(error) => {
                        return (
                            tokens,
                            Some(Diagnostic::new(
                                "invalid_string",
                                error.to_string(),
                                start,
                                index,
                            )),
                        );
                    }
                }
            }
            byte if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' => {
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || bytes[index] == b'_'
                        || bytes[index] == b'-')
                {
                    index += 1;
                }
                TokenKind::Word(text[start..index].to_owned())
            }
            _ => {
                let end = start + text[start..].chars().next().map_or(1, char::len_utf8);
                return (
                    tokens,
                    Some(Diagnostic::new(
                        "unexpected_character",
                        "unexpected character in the supported SOP source grammar",
                        start,
                        end,
                    )),
                );
            }
        };
        tokens.push(Token {
            kind,
            start,
            end: index,
        });
        if tokens.len() > 250_000 {
            return (
                tokens,
                Some(Diagnostic::new(
                    "token_limit",
                    "document exceeds 250000 tokens",
                    start,
                    index,
                )),
            );
        }
    }
    (tokens, None)
}

type ParseResult<T> = std::result::Result<T, Diagnostic>;

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    source: &'a SourceDocument,
    namespace: &'a str,
}

#[derive(Default)]
struct Fields {
    meaning: Option<String>,
    kind: Option<Id>,
    context: Option<Id>,
    namespace: Option<String>,
    status: Option<Status>,
    aliases: BTreeSet<String>,
    scopes: BTreeSet<String>,
    purposes: BTreeSet<String>,
    perspectives: BTreeSet<String>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    roles: Vec<Role>,
    relation_type: Option<Id>,
    participants: Vec<Participant>,
    guard: Option<Expr>,
    condition: Option<Expr>,
    conclusion: Option<Id>,
    units: BTreeSet<Id>,
    relations: BTreeSet<Id>,
}

impl Parser<'_> {
    fn position(&self) -> usize {
        self.tokens
            .get(self.at)
            .map_or(self.source.text.len(), |token| token.start)
    }

    fn error(&self, code: &str, message: impl Into<String>) -> Diagnostic {
        Diagnostic::new(
            code,
            message,
            self.position(),
            self.tokens
                .get(self.at)
                .map_or(self.source.text.len(), |token| token.end),
        )
    }

    fn token(&mut self) -> ParseResult<Token> {
        let token = self.tokens.get(self.at).cloned().ok_or_else(|| {
            self.error(
                "unexpected_eof",
                "source ended before the declaration was complete",
            )
        })?;
        self.at += 1;
        Ok(token)
    }

    fn word(&mut self) -> ParseResult<String> {
        let token = self.token()?;
        if let TokenKind::Word(value) = token.kind {
            Ok(value)
        } else {
            Err(Diagnostic::new(
                "expected_word",
                "expected a field name or keyword",
                token.start,
                token.end,
            ))
        }
    }

    fn id(&mut self) -> ParseResult<String> {
        let token = self.token()?;
        if let TokenKind::Id(value) = token.kind {
            if let Err(fault) = crate::validate::identifier(&value) {
                return Err(Diagnostic::new(
                    &fault.code,
                    fault.message,
                    token.start,
                    token.end,
                ));
            }
            Ok(value)
        } else {
            Err(Diagnostic::new(
                "expected_identifier",
                "expected [stable:identifier]",
                token.start,
                token.end,
            ))
        }
    }

    fn text(&mut self) -> ParseResult<String> {
        let token = self.token()?;
        if let TokenKind::Text(value) = token.kind {
            if value.len() > 65_536 || value.trim().is_empty() || value.contains('\0') {
                return Err(Diagnostic::new(
                    "invalid_text",
                    "quoted text must contain 1..65536 UTF-8 bytes, have non-whitespace content, and contain no NUL",
                    token.start,
                    token.end,
                ));
            }
            Ok(value)
        } else {
            Err(Diagnostic::new(
                "expected_string",
                "expected a JSON quoted string",
                token.start,
                token.end,
            ))
        }
    }

    fn expect(&mut self, kind: TokenKind, name: &str) -> ParseResult<Token> {
        let token = self.token()?;
        if token.kind == kind {
            Ok(token)
        } else {
            Err(Diagnostic::new(
                "expected_token",
                format!("expected {name}"),
                token.start,
                token.end,
            ))
        }
    }

    fn is(&self, kind: &TokenKind) -> bool {
        self.tokens
            .get(self.at)
            .is_some_and(|token| &token.kind == kind)
    }

    fn list(&mut self, ids: bool) -> ParseResult<BTreeSet<String>> {
        self.expect(TokenKind::Left, "(")?;
        let mut values = BTreeSet::new();
        if !self.is(&TokenKind::Right) {
            loop {
                let start = self.position();
                let value = if ids { self.id()? } else { self.text()? };
                if !values.insert(value) {
                    return Err(Diagnostic::new(
                        "duplicate_list_item",
                        "set membership is duplicated",
                        start,
                        self.position(),
                    ));
                }
                if values.len() > 10_000 {
                    return Err(self.error("list_limit", "list exceeds 10000 items"));
                }
                if !self.is(&TokenKind::Comma) {
                    break;
                }
                self.at += 1;
            }
        }
        self.expect(TokenKind::Right, ")")?;
        Ok(values)
    }

    fn expr(&mut self, depth: usize) -> ParseResult<Expr> {
        if depth > 16 {
            return Err(self.error("expression_limit", "guard exceeds depth 16"));
        }
        let operator = self.word()?;
        self.expect(TokenKind::Left, "(")?;
        let result = match operator.as_str() {
            "fact" => Expr::Fact { unit: self.id()? },
            "not" => Expr::Not {
                arg: Box::new(self.expr(depth + 1)?),
            },
            "all" | "any" => {
                let mut args = Vec::new();
                if !self.is(&TokenKind::Right) {
                    loop {
                        args.push(self.expr(depth + 1)?);
                        if args.len() > 64 {
                            return Err(self
                                .error("expression_limit", "all/any support at most 64 operands"));
                        }
                        if !self.is(&TokenKind::Comma) {
                            break;
                        }
                        self.at += 1;
                    }
                }
                if args.is_empty() {
                    return Err(
                        self.error("expression_arity", "all/any require at least one operand")
                    );
                }
                if operator == "all" {
                    Expr::All { args }
                } else {
                    Expr::Any { args }
                }
            }
            _ => {
                return Err(self.error(
                    "unsupported_operator",
                    format!("unsupported guard operator {operator}"),
                ));
            }
        };
        self.expect(TokenKind::Right, ")")?;
        Ok(result)
    }

    fn integer<T: std::str::FromStr>(&mut self) -> ParseResult<T> {
        let start = self.position();
        let value = self.word()?;
        value.parse().map_err(|_| {
            Diagnostic::new(
                "invalid_integer",
                "integer is invalid or out of range",
                start,
                self.position(),
            )
        })
    }

    fn declaration(&mut self, output: &mut Declarations) -> ParseResult<()> {
        let start = self.position();
        let family = self.word()?;
        if !matches!(
            family.as_str(),
            "kind" | "context" | "term" | "relation-type" | "relation" | "rule" | "view"
        ) {
            return Err(Diagnostic::new(
                "unknown_declaration",
                format!("unsupported declaration {family}"),
                start,
                self.position(),
            ));
        }
        let id = self.id()?;
        let label = if matches!(family.as_str(), "context" | "relation") {
            String::new()
        } else {
            self.text()?
        };
        self.expect(TokenKind::Open, "{")?;
        let mut fields = Fields::default();
        let mut seen = BTreeSet::new();
        while !self.is(&TokenKind::Close) {
            let field_start = self.position();
            let field = self.word()?;
            if !allowed_field(&family, &field) {
                return Err(Diagnostic::new(
                    "unknown_field",
                    format!("{field} is not a field of {family}"),
                    field_start,
                    self.position(),
                ));
            }
            if !matches!(field.as_str(), "role" | "participant") && !seen.insert(field.clone()) {
                return Err(Diagnostic::new(
                    "duplicate_field",
                    format!("{field} was already supplied"),
                    field_start,
                    self.position(),
                ));
            }
            match field.as_str() {
                "meaning" => fields.meaning = Some(self.text()?),
                "kind" => fields.kind = Some(self.id()?),
                "context" => fields.context = Some(self.id()?),
                "namespace" => fields.namespace = Some(self.text()?),
                "aliases" => fields.aliases = self.list(false)?,
                "status" => {
                    fields.status = Some(match self.word()?.as_str() {
                        "authored" => Status::Authored,
                        "unresolved" => Status::Unresolved,
                        "superseded" => Status::Superseded,
                        _ => {
                            return Err(self.error(
                                "unsupported_status",
                                "status must be authored, unresolved, or superseded",
                            ));
                        }
                    });
                }
                "scopes" => fields.scopes = self.list(false)?,
                "purposes" => fields.purposes = self.list(false)?,
                "perspectives" => fields.perspectives = self.list(false)?,
                "not-before" => fields.not_before = Some(self.integer()?),
                "not-after" => fields.not_after = Some(self.integer()?),
                "role" => {
                    let name = self.word()?;
                    let flow = match self.word()?.as_str() {
                        "input" => Flow::Input,
                        "output" => Flow::Output,
                        "member" => Flow::Member,
                        _ => {
                            return Err(self.error(
                                "unsupported_flow",
                                "role flow must be input, output, or member",
                            ));
                        }
                    };
                    let allowed_kinds = self.list(true)?;
                    let minimum = self.integer()?;
                    self.expect(TokenKind::Range, "..")?;
                    let maximum = self.integer()?;
                    fields.roles.push(Role {
                        name,
                        allowed_kinds,
                        minimum,
                        maximum,
                        flow,
                    });
                }
                "type" => fields.relation_type = Some(self.id()?),
                "participant" => fields.participants.push(Participant {
                    role: self.word()?,
                    unit: self.id()?,
                }),
                "guard" => fields.guard = Some(self.expr(0)?),
                "when" => fields.condition = Some(self.expr(0)?),
                "then" => fields.conclusion = Some(self.id()?),
                "units" => fields.units = self.list(true)?,
                "relations" => fields.relations = self.list(true)?,
                _ => unreachable!("allowed fields are exhaustively parsed"),
            }
        }
        let end = self.expect(TokenKind::Close, "}")?.end;
        let source = SourceSpan {
            source: self.source.id.clone(),
            start: start as u64,
            end: end as u64,
        };
        let package = self.source.package.clone();
        macro_rules! required {
            ($field:expr,$name:expr) => {
                $field.ok_or_else(|| {
                    Diagnostic::new(
                        "missing_field",
                        format!("{family} {id} requires {}", $name),
                        start,
                        end,
                    )
                })?
            };
        }
        match family.as_str() {
            "kind" => output.kinds.push(Kind {
                id: id.clone(),
                package,
                label,
                meaning: required!(fields.meaning, "meaning"),
                source,
            }),
            "context" => output.contexts.push(Context {
                id: id.clone(),
                package,
                scopes: fields.scopes,
                purposes: fields.purposes,
                perspectives: fields.perspectives,
                validity: Validity {
                    not_before: fields.not_before,
                    not_after: fields.not_after,
                },
                source,
            }),
            "term" => output.units.push(Unit {
                id: id.clone(),
                package,
                namespace: fields
                    .namespace
                    .unwrap_or_else(|| self.namespace.to_owned()),
                kind: required!(fields.kind, "kind"),
                label,
                aliases: fields.aliases,
                meaning: required!(fields.meaning, "meaning"),
                context: required!(fields.context, "context"),
                status: fields.status.unwrap_or(Status::Authored),
                source,
            }),
            "relation-type" => output.relation_types.push(RelationType {
                id: id.clone(),
                package,
                label,
                meaning: required!(fields.meaning, "meaning"),
                roles: fields.roles,
                source,
            }),
            "relation" => output.relations.push(Relation {
                id: id.clone(),
                package,
                relation_type: required!(fields.relation_type, "type"),
                participants: fields.participants,
                context: required!(fields.context, "context"),
                guard: fields.guard,
                source,
            }),
            "rule" => output.rules.push(Rule {
                id: id.clone(),
                package,
                label,
                context: required!(fields.context, "context"),
                condition: required!(fields.condition, "when"),
                conclusion: required!(fields.conclusion, "then"),
                source,
            }),
            "view" => output.views.push(View {
                id: id.clone(),
                package,
                label,
                context: required!(fields.context, "context"),
                units: fields.units,
                relations: fields.relations,
                source,
            }),
            _ => unreachable!(),
        }
        Ok(())
    }

    fn recover(&mut self) {
        while self.at < self.tokens.len() {
            let token = &self.tokens[self.at];
            if let TokenKind::Word(name) = &token.kind
                && matches!(
                    name.as_str(),
                    "kind" | "context" | "term" | "relation-type" | "relation" | "rule" | "view"
                )
                && self
                    .tokens
                    .get(self.at + 1)
                    .is_some_and(|next| matches!(next.kind, TokenKind::Id(_)))
                && self.tokens.get(self.at + 2).is_some_and(|next| {
                    if matches!(name.as_str(), "context" | "relation") {
                        next.kind == TokenKind::Open
                    } else {
                        matches!(next.kind, TokenKind::Text(_))
                    }
                })
            {
                break;
            }
            self.at += 1;
        }
    }
}

fn allowed_field(family: &str, field: &str) -> bool {
    fields_for(family).contains(&field)
}

pub fn fields_for(family: &str) -> &'static [&'static str] {
    match family {
        "kind" => &["meaning"],
        "context" => &[
            "scopes",
            "purposes",
            "perspectives",
            "not-before",
            "not-after",
        ],
        "term" => &[
            "kind",
            "context",
            "meaning",
            "aliases",
            "namespace",
            "status",
        ],
        "relation-type" => &["meaning", "role"],
        "relation" => &["type", "context", "participant", "guard"],
        "rule" => &["context", "when", "then"],
        "view" => &["context", "units", "relations"],
        _ => &[],
    }
}

pub fn analyze(source: &SourceDocument, namespace: &str) -> DocumentAnalysis {
    if source.text.len() > MAX_DOCUMENT_BYTES {
        return DocumentAnalysis {
            profile: SOURCE_PROFILE.to_owned(),
            declarations: Declarations::default(),
            diagnostics: vec![Diagnostic::new(
                "document_limit",
                "source document exceeds 2 MiB",
                0,
                0,
            )],
            complete: false,
        };
    }
    let (mut tokens, lex_error) = lex(&source.text);
    tokens.retain(|token| token.kind != TokenKind::Comment);
    let mut parser = Parser {
        tokens,
        at: 0,
        source,
        namespace,
    };
    let mut declarations = Declarations::default();
    let mut diagnostics = Vec::new();
    while parser.at < parser.tokens.len() && diagnostics.len() < MAX_DIAGNOSTICS {
        let before = parser.at;
        if let Err(error) = parser.declaration(&mut declarations) {
            diagnostics.push(error);
            if parser.at == before {
                parser.at += 1;
            }
            parser.recover();
        }
    }
    if let Some(error) = lex_error
        && diagnostics.len() < MAX_DIAGNOSTICS
    {
        diagnostics.push(error);
    }
    DocumentAnalysis {
        profile: SOURCE_PROFILE.to_owned(),
        complete: diagnostics.is_empty(),
        declarations,
        diagnostics,
    }
}
