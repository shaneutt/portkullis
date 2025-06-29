// -----------------------------------------------------------------------------
// Signature-Based Detection Engine - Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationErrors {
    EmptyRule,
    InvalidFormat { expected: usize, found: usize },
    InvalidDirective { found: String },
    InvalidRuleId { value: String },
    InvalidPhase { value: String },
    InvalidSeverity { value: String },
    InvalidVariable { value: String },
    InvalidOperator { value: String },
    EmptyVariable,
    EmptyOperator,
    EmptyActions,
}

impl std::fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationErrors::EmptyRule => {
                write!(f, "Rule string is empty or contains only whitespace")
            }
            ValidationErrors::InvalidFormat { expected, found } => {
                write!(
                    f,
                    "Invalid rule format: expected {} parts, found {}",
                    expected, found
                )
            }
            ValidationErrors::InvalidDirective { found } => {
                write!(
                    f,
                    "Invalid directive: expected 'SecRule', found '{}'",
                    found
                )
            }
            ValidationErrors::InvalidRuleId { value } => {
                write!(f, "Invalid rule ID: '{}' is not a valid number", value)
            }
            ValidationErrors::InvalidPhase { value } => {
                write!(f, "Invalid phase: '{}' is not a valid phase", value)
            }
            ValidationErrors::InvalidSeverity { value } => {
                write!(
                    f,
                    "Invalid severity: '{}' is not a valid severity (0-7)",
                    value
                )
            }
            ValidationErrors::InvalidVariable { value } => {
                write!(f, "Invalid variable: '{}' is not a valid variable", value)
            }
            ValidationErrors::InvalidOperator { value } => {
                write!(f, "Invalid operator: '{}' is not a valid operator", value)
            }
            ValidationErrors::EmptyVariable => write!(f, "Variable cannot be empty"),
            ValidationErrors::EmptyOperator => write!(f, "Operator cannot be empty"),
            ValidationErrors::EmptyActions => write!(f, "Actions cannot be empty"),
        }
    }
}
