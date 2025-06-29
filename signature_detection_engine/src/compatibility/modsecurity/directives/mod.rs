pub mod consts;
pub mod parsers;
pub mod sec_marker;
pub mod sec_rule;

#[derive(Clone, Debug, PartialEq)]
pub enum Directive {
    SecRule(sec_rule::SecRule),
    SecMarker(sec_marker::SecMarker),
}
