mod compatibility;
pub mod errors;

use std::collections::HashMap;
use std::sync::Mutex;

use crate::compatibility::modsecurity::directives::{
    Directive,
    parsers::sec_rule::parse_sec_rule,
    sec_rule::{Operator, Phase, SecRule, Variable},
};
use crate::compatibility::modsecurity::rulesets::{RuleGroup, RuleSet};

// -----------------------------------------------------------------------------
// Signature-Based Detection Engine
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct SignatureBasedDetectionEngine {
    pub counter: Mutex<u64>,
    pub rule_group: RuleGroup,
}

impl SignatureBasedDetectionEngine {
    pub fn new(rule_group: RuleGroup) -> Self {
        Self {
            rule_group,
            counter: Mutex::new(0),
        }
    }

    // some example rules, for testing purposes
    pub fn new_example() -> Self {
        // curl -H "User-Agent: malicious-bot" http://127.0.0.1
        let rule1 = r#"SecRule REQUEST_HEADERS:User-Agent \
        "@contains bot" \
        "id:1001,\
        phase:1,\
        deny,\
        msg:'bot detected',\
        severity:3,\
        tag:'attack/bot'""#;

        // curl -X POST -d "input=<script>alert('xss')</script>" http://127.0.0.1
        let rule2 = r#"SecRule ARGS \
        "@contains <script" \
        "id:1002,\
        phase:2,\
        deny,\
        msg:'XSS attempt detected',\
        severity:2,\
        tag:'attack/xss'""#;

        // curl "http://127.0.0.1/test?search=%3Cscript%3E" (URL-encoded XSS)
        let rule2b = r#"SecRule ARGS \
        "@contains %3Cscript" \
        "id:1004,\
        phase:2,\
        deny,\
        msg:'URL-encoded XSS attempt detected',\
        severity:2,\
        tag:'attack/xss'""#;

        // curl -X POST -H "Content-Type: application/json" -d '{"user": "Robert');DROP TABLE users;--"}' http://127.0.0.1
        let rule3 = r#"SecRule REQUEST_BODY \
        "@contains DROP TABLE" \
        "id:1003,\
        phase:2,\
        deny,\
        msg:'SQL injection attempt detected in request body',\
        severity:2,\
        tag:'attack/sqli'""#;

        let sec_rule_header_1 = parse_sec_rule(rule1.to_string()).unwrap();
        let sec_rule_body_1 = parse_sec_rule(rule2.to_string()).unwrap();
        let sec_rule_body_1b = parse_sec_rule(rule2b.to_string()).unwrap();
        let sec_rule_body_2 = parse_sec_rule(rule3.to_string()).unwrap();

        let mut rule_group = HashMap::new();

        let phase1_directives = vec![Directive::SecRule(sec_rule_header_1)];
        let phase1_ruleset = RuleSet::new(
            "Request Header Phase Rules".to_string(),
            "Request header processing rules".to_string(),
            "0.0.1".to_string(),
            phase1_directives,
        );
        rule_group.insert(Phase::RequestHeaders, vec![phase1_ruleset]);

        let phase2_directives = vec![
            Directive::SecRule(sec_rule_body_1),
            Directive::SecRule(sec_rule_body_1b),
            Directive::SecRule(sec_rule_body_2),
        ];
        let phase2_ruleset = RuleSet::new(
            "Request Body Phase Rules".to_string(),
            "Request body processing rules".to_string(),
            "0.0.1".to_string(),
            phase2_directives,
        );
        rule_group.insert(Phase::RequestBody, vec![phase2_ruleset]);

        Self {
            rule_group,
            counter: Mutex::new(0),
        }
    }

    pub fn run_header_phase(
        &self,
        headers: Vec<(String, String)>,
    ) -> Result<Option<SecRule>, String> {
        let header_rulesets = match self.rule_group.get(&Phase::RequestHeaders) {
            Some(rulesets) => rulesets,
            None => return Ok(None),
        };

        for ruleset in header_rulesets {
            if let Some(matched_rule) = check_ruleset_against_headers(ruleset, &headers)? {
                return Ok(Some(matched_rule));
            }
        }

        Ok(None)
    }

    pub fn run_args_phase(&self, query_string: &str) -> Result<Option<SecRule>, String> {
        let header_rulesets = match self.rule_group.get(&Phase::RequestBody) {
            Some(rulesets) => rulesets,
            None => return Ok(None),
        };

        for ruleset in header_rulesets {
            if let Some(matched_rule) = check_ruleset_against_args(ruleset, query_string)? {
                return Ok(Some(matched_rule));
            }
        }

        Ok(None)
    }

    pub fn run_body_phase(&self, body: &str) -> Result<Option<SecRule>, String> {
        let body_rulesets = match self.rule_group.get(&Phase::RequestBody) {
            Some(rulesets) => rulesets,
            None => return Ok(None),
        };

        for ruleset in body_rulesets {
            if let Some(matched_rule) = check_ruleset_against_body(ruleset, body)? {
                return Ok(Some(matched_rule));
            }
        }

        Ok(None)
    }
}

// -----------------------------------------------------------------------------
// Private Helper Functions
// -----------------------------------------------------------------------------

fn check_ruleset_against_headers(
    ruleset: &RuleSet,
    headers: &[(String, String)],
) -> Result<Option<SecRule>, String> {
    for directive in &ruleset.directives {
        if let Directive::SecRule(sec_rule) = directive {
            if let Some(matched_rule) = check_rule_against_headers(sec_rule, headers)? {
                return Ok(Some(matched_rule));
            }
        }
    }
    Ok(None)
}

fn check_rule_against_headers(
    sec_rule: &SecRule,
    headers: &[(String, String)],
) -> Result<Option<SecRule>, String> {
    if sec_rule.variable != Variable::RequestHeaders {
        return Ok(None);
    }

    if sec_rule.operator != Operator::Contains {
        return Err(format!(
            "{:?} operator is not yet implemented. rule: {}",
            sec_rule.operator, sec_rule.id
        ));
    }

    if rule_matches_headers(sec_rule, headers) {
        Ok(Some(sec_rule.clone()))
    } else {
        Ok(None)
    }
}

fn rule_matches_headers(sec_rule: &SecRule, headers: &[(String, String)]) -> bool {
    let variable_target = match &sec_rule.variable_target {
        Some(target) => target,
        None => return false,
    };

    let operator_target = match &sec_rule.operator_target {
        Some(target) => target,
        None => return false,
    };

    for (name, value) in headers {
        if name.eq_ignore_ascii_case(variable_target) {
            if value
                .to_ascii_lowercase()
                .contains(&operator_target.to_ascii_lowercase())
            {
                return true;
            }
        }
    }

    false
}

fn check_ruleset_against_args(
    ruleset: &RuleSet,
    query_string: &str,
) -> Result<Option<SecRule>, String> {
    for directive in &ruleset.directives {
        if let Directive::SecRule(sec_rule) = directive {
            if let Some(matched_rule) = check_rule_against_args(sec_rule, query_string)? {
                return Ok(Some(matched_rule));
            }
        }
    }
    Ok(None)
}

fn check_rule_against_args(
    sec_rule: &SecRule,
    query_string: &str,
) -> Result<Option<SecRule>, String> {
    if sec_rule.variable != Variable::Args {
        return Ok(None);
    }

    if sec_rule.operator != Operator::Contains {
        return Err(format!(
            "{:?} operator is not yet implemented. rule: {}",
            sec_rule.operator, sec_rule.id
        ));
    }

    if rule_matches_args(sec_rule, query_string) {
        Ok(Some(sec_rule.clone()))
    } else {
        Ok(None)
    }
}

fn rule_matches_args(sec_rule: &SecRule, query_string: &str) -> bool {
    let operator_target = match &sec_rule.operator_target {
        Some(target) => target,
        None => return false,
    };

    query_string
        .to_ascii_lowercase()
        .contains(&operator_target.to_ascii_lowercase())
}

fn check_ruleset_against_body(ruleset: &RuleSet, body: &str) -> Result<Option<SecRule>, String> {
    for directive in &ruleset.directives {
        if let Directive::SecRule(sec_rule) = directive {
            if let Some(matched_rule) = check_rule_against_body(sec_rule, body)? {
                return Ok(Some(matched_rule));
            }
        }
    }
    Ok(None)
}

fn check_rule_against_body(sec_rule: &SecRule, body: &str) -> Result<Option<SecRule>, String> {
    if sec_rule.variable != Variable::RequestBody {
        return Ok(None);
    }

    if sec_rule.operator != Operator::Contains {
        return Err(format!(
            "{:?} operator is not yet implemented. rule: {}",
            sec_rule.operator, sec_rule.id
        ));
    }

    if rule_matches_body(sec_rule, body) {
        Ok(Some(sec_rule.clone()))
    } else {
        Ok(None)
    }
}

fn rule_matches_body(sec_rule: &SecRule, body: &str) -> bool {
    let operator_target = match &sec_rule.operator_target {
        Some(target) => target,
        None => return false,
    };

    body.to_ascii_lowercase()
        .contains(&operator_target.to_ascii_lowercase())
}
