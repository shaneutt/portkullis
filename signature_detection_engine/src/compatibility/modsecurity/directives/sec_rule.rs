use super::consts::*;
use crate::compatibility::modsecurity::directives::parsers::sec_rule::parse_sec_rule;
use crate::errors::ValidationErrors;

// -----------------------------------------------------------------------------
// ModSecurity - SecRule
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct SecRule {
    pub id: u32,
    pub phase: Phase,
    pub action: String,
    pub operator: Operator,
    pub operator_target: Option<String>,
    pub variable: Variable,
    pub variable_target: Option<String>,
    pub pattern: String,
    pub transformations: Vec<String>,
    pub tags: Vec<String>,
    pub message: Option<String>,
    pub severity: Option<Severity>,
    pub chain: bool,
}

impl Default for SecRule {
    fn default() -> Self {
        SecRule {
            id: 0,
            phase: Phase::default(),
            action: String::new(),
            operator: Operator::default(),
            operator_target: None,
            variable: Variable::default(),
            variable_target: None,
            pattern: String::new(),
            transformations: Vec::new(),
            tags: Vec::new(),
            message: None,
            severity: None,
            chain: false,
        }
    }
}

impl TryFrom<String> for SecRule {
    type Error = ValidationErrors;

    fn try_from(sec_rule_string: String) -> Result<Self, Self::Error> {
        parse_sec_rule(sec_rule_string)
    }
}

// -----------------------------------------------------------------------------
// ModSecurity - Phase
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    RequestHeaders = 1,
    RequestBody = 2,
    ResponseHeaders = 3,
    ResponseBody = 4,
    Logging = 5,
}

impl Default for Phase {
    fn default() -> Self {
        Phase::RequestHeaders
    }
}

impl TryFrom<u8> for Phase {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            1 => Ok(Phase::RequestHeaders),
            2 => Ok(Phase::RequestBody),
            3 => Ok(Phase::ResponseHeaders),
            4 => Ok(Phase::ResponseBody),
            5 => Ok(Phase::Logging),
            _ => Err(format!("invalid phase: {}", value)),
        }
    }
}

impl Into<u8> for Phase {
    fn into(self) -> u8 {
        self as u8
    }
}

// -----------------------------------------------------------------------------
// ModSecurity - Severity
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Emergency
    }
}

impl TryFrom<u8> for Severity {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0 => Ok(Severity::Emergency),
            1 => Ok(Severity::Alert),
            2 => Ok(Severity::Critical),
            3 => Ok(Severity::Error),
            4 => Ok(Severity::Warning),
            5 => Ok(Severity::Notice),
            6 => Ok(Severity::Info),
            7 => Ok(Severity::Debug),
            _ => Err(format!("invalid severity: {}", value)),
        }
    }
}

impl Into<u8> for Severity {
    fn into(self) -> u8 {
        self as u8
    }
}

// -----------------------------------------------------------------------------
// ModSecurity - Operator
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Operator {
    // TODO: implement more operators
    Contains,
}

impl Default for Operator {
    fn default() -> Self {
        Operator::Contains
    }
}

impl TryFrom<&str> for Operator {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let op_str = s.strip_prefix('@').unwrap_or(s);
        match op_str.to_lowercase().as_str() {
            "contains" => Ok(Operator::Contains),
            _ => Err(format!("operator type unknown (or unimplemented): '{}'", s)),
        }
    }
}

// -----------------------------------------------------------------------------
// ModSecurity - Variable
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Variable {
    // TODO: implement more variables
    RequestHeaders,
    ResponseHeaders,
    RequestBody,
    Args,
}

impl Default for Variable {
    fn default() -> Self {
        Variable::RequestHeaders
    }
}

impl TryFrom<&str> for Variable {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_uppercase().as_str() {
            REQUEST_HEADERS => Ok(Variable::RequestHeaders),
            REQUEST_BODY => Ok(Variable::RequestBody),
            ARGS => Ok(Variable::Args),
            _ => Err(format!("unknown variable type: '{}'", s)),
        }
    }
}
