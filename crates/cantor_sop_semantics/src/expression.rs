use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Expr, Id, Truth};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpressionEvaluation {
    pub truth: Truth,
    pub observed: BTreeMap<Id, Truth>,
}

pub fn evaluate(expr: &Expr, facts: &BTreeMap<Id, Truth>) -> ExpressionEvaluation {
    let mut observed = BTreeMap::new();
    let truth = evaluate_inner(expr, facts, &mut observed);
    ExpressionEvaluation { truth, observed }
}

fn evaluate_inner(
    expr: &Expr,
    facts: &BTreeMap<Id, Truth>,
    observed: &mut BTreeMap<Id, Truth>,
) -> Truth {
    match expr {
        Expr::Fact { unit } => {
            let truth = facts.get(unit).copied().unwrap_or(Truth::Unknown);
            observed.insert(unit.clone(), truth);
            truth
        }
        Expr::Not { arg } => match evaluate_inner(arg, facts, observed) {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            Truth::Unknown => Truth::Unknown,
        },
        Expr::All { args } => {
            let mut unknown = false;
            for arg in args {
                match evaluate_inner(arg, facts, observed) {
                    Truth::False => return Truth::False,
                    Truth::Unknown => unknown = true,
                    Truth::True => {}
                }
            }
            if unknown { Truth::Unknown } else { Truth::True }
        }
        Expr::Any { args } => {
            let mut unknown = false;
            for arg in args {
                match evaluate_inner(arg, facts, observed) {
                    Truth::True => return Truth::True,
                    Truth::Unknown => unknown = true,
                    Truth::False => {}
                }
            }
            if unknown {
                Truth::Unknown
            } else {
                Truth::False
            }
        }
    }
}
