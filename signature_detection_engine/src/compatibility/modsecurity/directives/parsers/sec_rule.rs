use crate::compatibility::modsecurity::directives::sec_rule::{
    Operator, Phase, SecRule, Severity, Variable,
};
use crate::errors::ValidationErrors;

// -----------------------------------------------------------------------------
// ModSecurity - SecRule Parser
// -----------------------------------------------------------------------------

// Parser to convert a ModSecurity SecRule string into a structured SecRule Object.
//
// Reference: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)#user-content-SecRule
pub(crate) fn parse_sec_rule(raw_sec_rule: String) -> Result<SecRule, ValidationErrors> {
    let sec_rule_components = validate_sec_rule(raw_sec_rule)?;
    let (operator, operator_target) = parse_operator_string(&sec_rule_components.operator)?;
    let mut sec_rule = SecRule {
        variable: sec_rule_components.variable,
        variable_target: sec_rule_components.variable_target,
        operator,
        operator_target,
        pattern: String::new(),
        ..SecRule::default()
    };

    for action_part in sec_rule_components.actions_str.split(',') {
        let action_part = action_part.trim();

        if let Some((key, value)) = action_part.split_once(':') {
            match key {
                "id" => {
                    sec_rule.id =
                        value
                            .parse::<u32>()
                            .map_err(|_| ValidationErrors::InvalidRuleId {
                                value: value.to_string(),
                            })?;
                }
                "phase" => {
                    let parsed_phase =
                        value
                            .parse::<u8>()
                            .map_err(|_| ValidationErrors::InvalidPhase {
                                value: value.to_string(),
                            })?;
                    sec_rule.phase = Phase::try_from(parsed_phase).map_err(|_| {
                        ValidationErrors::InvalidPhase {
                            value: value.to_string(),
                        }
                    })?;
                }
                "msg" => {
                    sec_rule.message = Some(value.trim_matches('\'').to_string());
                }
                "severity" => {
                    let parsed_severity =
                        value
                            .parse::<u8>()
                            .map_err(|_| ValidationErrors::InvalidSeverity {
                                value: value.to_string(),
                            })?;
                    sec_rule.severity =
                        Some(Severity::try_from(parsed_severity).map_err(|_| {
                            ValidationErrors::InvalidSeverity {
                                value: value.to_string(),
                            }
                        })?);
                }
                "tag" => {
                    sec_rule.tags.push(value.trim_matches('\'').to_string());
                }
                "t" => {
                    sec_rule.transformations.push(value.to_string());
                }
                unknown_key => {
                    return Err(ValidationErrors::InvalidDirective {
                        found: unknown_key.to_string(),
                    });
                }
            }
        } else {
            if !action_part.is_empty() {
                sec_rule.action = action_part.to_string();
            }
        }
    }

    Ok(sec_rule)
}

// -----------------------------------------------------------------------------
// ModSecurity - SecRule Validation
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ValidatedSecRuleComponents {
    pub variable: Variable,
    pub variable_target: Option<String>,
    pub operator: String,
    pub actions_str: String,
}

pub(crate) fn validate_sec_rule(
    raw_sec_rule: String,
) -> Result<ValidatedSecRuleComponents, ValidationErrors> {
    if raw_sec_rule.trim().is_empty() {
        return Err(ValidationErrors::EmptyRule);
    }

    let sec_rule = raw_sec_rule
        .replace("\\\n", " ")
        .replace("\\", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut parts = Vec::new();
    let mut current_part = String::new();
    let mut in_quotes = false;
    let mut chars = sec_rule.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    parts.push(current_part.clone());
                    current_part.clear();
                    in_quotes = false;
                } else {
                    if !current_part.is_empty() {
                        parts.push(current_part.clone());
                        current_part.clear();
                    }
                    in_quotes = true;
                }
            }
            ' ' if !in_quotes => {
                if !current_part.is_empty() {
                    parts.push(current_part.clone());
                    current_part.clear();
                }
            }
            _ => {
                current_part.push(ch);
            }
        }
    }

    if !current_part.is_empty() {
        parts.push(current_part);
    }

    if parts.len() != 4 {
        return Err(ValidationErrors::InvalidFormat {
            expected: 4,
            found: parts.len(),
        });
    }

    if parts[0] != "SecRule" {
        return Err(ValidationErrors::InvalidDirective {
            found: parts[0].to_string(),
        });
    }

    let variable_str = &parts[1];
    if variable_str.is_empty() {
        return Err(ValidationErrors::EmptyVariable);
    }

    let (variable, variable_target) = match variable_str.split_once(':') {
        Some((var_type, target)) => {
            let variable =
                Variable::try_from(var_type).map_err(|_| ValidationErrors::InvalidVariable {
                    value: var_type.to_string(),
                })?;
            (variable, Some(target.to_string()))
        }
        None => {
            let variable = Variable::try_from(variable_str.as_str()).map_err(|_| {
                ValidationErrors::InvalidVariable {
                    value: variable_str.to_string(),
                }
            })?;
            (variable, None)
        }
    };

    let operator_str = &parts[2];
    if operator_str.is_empty() {
        return Err(ValidationErrors::EmptyOperator);
    }
    let operator = operator_str.to_string();

    let actions_str = &parts[3];
    if actions_str.is_empty() {
        return Err(ValidationErrors::EmptyActions);
    }

    Ok(ValidatedSecRuleComponents {
        variable,
        variable_target,
        operator,
        actions_str: actions_str.to_string(),
    })
}

fn parse_operator_string(
    operator_str: &str,
) -> Result<(Operator, Option<String>), ValidationErrors> {
    if let Some((op_part, target_part)) = operator_str.split_once(' ') {
        let operator =
            Operator::try_from(op_part).map_err(|_| ValidationErrors::InvalidOperator {
                value: op_part.to_string(),
            })?;
        let target = if target_part.trim().is_empty() {
            None
        } else {
            Some(target_part.trim().to_string())
        };
        Ok((operator, target))
    } else {
        let operator =
            Operator::try_from(operator_str).map_err(|_| ValidationErrors::InvalidOperator {
                value: operator_str.to_string(),
            })?;
        Ok((operator, None))
    }
}
