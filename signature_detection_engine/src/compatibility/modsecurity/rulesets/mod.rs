use std::collections::HashMap;

use crate::compatibility::modsecurity::directives::{Directive, sec_rule::Phase};

// -----------------------------------------------------------------------------
// ModSecurity - RuleSet
// -----------------------------------------------------------------------------

pub type RuleGroup = HashMap<Phase, RuleSets>;

pub type RuleSets = Vec<RuleSet>;

#[derive(Clone, Debug, PartialEq)]
pub struct RuleSet {
    pub name: Option<String>,
    pub description: Option<String>,
    pub directives: Vec<Directive>,
    pub version: Option<String>,
}

impl RuleSet {
    pub fn new(
        name: String,
        description: String,
        version: String,
        directives: Vec<Directive>,
    ) -> Self {
        RuleSet {
            name: Some(name),
            description: Some(description),
            directives: directives,
            version: Some(version),
        }
    }
}
