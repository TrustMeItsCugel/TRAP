//! Application-layer contents format: operations, distributions, ranges,
//! and dependent selections. See Protocol Spec §8.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Maximum allowed dependency chain depth.
pub const MAX_DEPENDENCY_DEPTH: usize = 6;

/// The set of possible outcomes a server commits to for a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contents {
    pub operations: Vec<Operation>,
}

/// A single random operation within the contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    /// Unique (within the contents) identifier; used as the domain
    /// separator when deriving this operation's random value.
    pub id: String,
    /// If set, this operation's outcome table is selected by the
    /// result of the named operation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub depends_on: Option<String>,
    #[serde(flatten)]
    pub op: OperationType,
}

/// Inclusive integer range parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeParams {
    pub min: i64,
    pub max: i64,
}

/// The kind of random operation to perform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OperationType {
    /// Weighted selection from named outcomes. Weights are positive integers.
    Distribution { outcomes: IndexMap<String, u64> },
    /// Random integer in `[min, max]` inclusive.
    Range {
        #[serde(flatten)]
        range: RangeParams,
    },
    /// Weighted selection where the outcome table depends on a parent
    /// operation's result.
    DependentDistribution {
        outcomes: IndexMap<String, IndexMap<String, u64>>,
    },
    /// Range where the bounds depend on a parent operation's result.
    DependentRange { ranges: IndexMap<String, RangeParams> },
}

/// The result of evaluating all operations in a session's contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub results: IndexMap<String, OutcomeValue>,
}

/// A single operation's result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutcomeValue {
    Selected(String),
    Number(i64),
}

/// Errors arising from invalid contents structure.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ContentsError {
    #[error("duplicate operation id: {0}")]
    DuplicateId(String),
    #[error("operation {0} depends on unknown operation {1}")]
    UnknownDependency(String, String),
    #[error("dependency chain exceeds maximum depth of {MAX_DEPENDENCY_DEPTH}")]
    DepthExceeded,
    #[error("circular dependency involving operation {0}")]
    CircularDependency(String),
    #[error("operation {0}: dependent operation must declare depends_on")]
    MissingDependsOn(String),
    #[error("operation {0}: non-dependent operation must not declare depends_on")]
    UnexpectedDependsOn(String),
    #[error("operation {0}: empty outcome table")]
    EmptyOutcomes(String),
    #[error("operation {0}: invalid range (min > max)")]
    InvalidRange(String),
    #[error("operation {0}: range too wide (span exceeds u64)")]
    RangeTooWide(String),
    #[error("operation {0}: weights sum to zero")]
    ZeroWeights(String),
    #[error("operation {0}: dependency result {1} not present in outcome table")]
    MissingDependencyBranch(String, String),
}

/// Whether an inclusive `[min, max]` range's span (`max - min + 1`) fits in
/// a `u64`. The only range that fails is the full-width `i64::MIN..=i64::MAX`
/// (span exactly 2^64). `outcome::pick_range` reduces the derived randomness
/// modulo this span, so a span that wrapped to zero would panic — `validate`
/// rejects it up front.
fn range_span_fits_u64(min: i64, max: i64) -> bool {
    (max as i128 - min as i128 + 1) <= u64::MAX as i128
}

impl Contents {
    /// Validate structural invariants: unique ids, resolvable dependencies,
    /// acyclic with depth <= MAX_DEPENDENCY_DEPTH, non-degenerate tables,
    /// and ranges whose span fits in a u64.
    pub fn validate(&self) -> Result<(), ContentsError> {
        use std::collections::HashMap;

        let mut index: HashMap<&str, &Operation> = HashMap::new();
        for op in &self.operations {
            if index.insert(op.id.as_str(), op).is_some() {
                return Err(ContentsError::DuplicateId(op.id.clone()));
            }
        }

        for op in &self.operations {
            // depends_on presence must match operation kind
            let is_dependent = matches!(
                op.op,
                OperationType::DependentDistribution { .. } | OperationType::DependentRange { .. }
            );
            match (&op.depends_on, is_dependent) {
                (None, true) => return Err(ContentsError::MissingDependsOn(op.id.clone())),
                (Some(_), false) => {
                    return Err(ContentsError::UnexpectedDependsOn(op.id.clone()))
                }
                _ => {}
            }

            if let Some(dep) = &op.depends_on {
                if !index.contains_key(dep.as_str()) {
                    return Err(ContentsError::UnknownDependency(op.id.clone(), dep.clone()));
                }
            }

            // Non-degenerate tables
            match &op.op {
                OperationType::Distribution { outcomes } => {
                    if outcomes.is_empty() {
                        return Err(ContentsError::EmptyOutcomes(op.id.clone()));
                    }
                    if outcomes.values().sum::<u64>() == 0 {
                        return Err(ContentsError::ZeroWeights(op.id.clone()));
                    }
                }
                OperationType::Range { range } => {
                    if range.min > range.max {
                        return Err(ContentsError::InvalidRange(op.id.clone()));
                    }
                    if !range_span_fits_u64(range.min, range.max) {
                        return Err(ContentsError::RangeTooWide(op.id.clone()));
                    }
                }
                OperationType::DependentDistribution { outcomes } => {
                    if outcomes.is_empty() {
                        return Err(ContentsError::EmptyOutcomes(op.id.clone()));
                    }
                    for table in outcomes.values() {
                        if table.is_empty() {
                            return Err(ContentsError::EmptyOutcomes(op.id.clone()));
                        }
                        if table.values().sum::<u64>() == 0 {
                            return Err(ContentsError::ZeroWeights(op.id.clone()));
                        }
                    }
                }
                OperationType::DependentRange { ranges } => {
                    if ranges.is_empty() {
                        return Err(ContentsError::EmptyOutcomes(op.id.clone()));
                    }
                    for r in ranges.values() {
                        if r.min > r.max {
                            return Err(ContentsError::InvalidRange(op.id.clone()));
                        }
                        if !range_span_fits_u64(r.min, r.max) {
                            return Err(ContentsError::RangeTooWide(op.id.clone()));
                        }
                    }
                }
            }
        }

        // Acyclicity + depth check by walking each chain.
        for op in &self.operations {
            let mut depth = 1usize;
            let mut current = op;
            let mut visited = vec![op.id.as_str()];
            while let Some(dep) = &current.depends_on {
                if visited.contains(&dep.as_str()) {
                    return Err(ContentsError::CircularDependency(dep.clone()));
                }
                depth += 1;
                if depth > MAX_DEPENDENCY_DEPTH {
                    return Err(ContentsError::DepthExceeded);
                }
                current = index[dep.as_str()];
                visited.push(current.id.as_str());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dist(id: &str, pairs: &[(&str, u64)]) -> Operation {
        Operation {
            id: id.into(),
            depends_on: None,
            op: OperationType::Distribution {
                outcomes: pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            },
        }
    }

    #[test]
    fn valid_contents_pass() {
        let c = Contents {
            operations: vec![dist("tier", &[("common", 7000), ("rare", 2500), ("epic", 500)])],
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn full_width_range_rejected() {
        // The full-width i64 range overflows the u64 span used by pick_range;
        // validate must reject it rather than letting it panic.
        let c = Contents {
            operations: vec![Operation {
                id: "r".into(),
                depends_on: None,
                op: OperationType::Range {
                    range: RangeParams {
                        min: i64::MIN,
                        max: i64::MAX,
                    },
                },
            }],
        };
        assert_eq!(c.validate(), Err(ContentsError::RangeTooWide("r".into())));
        // A merely large range that still fits in u64 remains valid.
        let ok = Contents {
            operations: vec![Operation {
                id: "r".into(),
                depends_on: None,
                op: OperationType::Range {
                    range: RangeParams {
                        min: 0,
                        max: i64::MAX,
                    },
                },
            }],
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn duplicate_ids_rejected() {
        let c = Contents {
            operations: vec![dist("a", &[("x", 1)]), dist("a", &[("y", 1)])],
        };
        assert_eq!(c.validate(), Err(ContentsError::DuplicateId("a".into())));
    }

    #[test]
    fn circular_dependency_rejected() {
        // a depends on b, b depends on a
        let mk = |id: &str, dep: &str| Operation {
            id: id.into(),
            depends_on: Some(dep.into()),
            op: OperationType::DependentDistribution {
                outcomes: [(
                    "x".to_string(),
                    [("y".to_string(), 1u64)].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            },
        };
        let c = Contents {
            operations: vec![mk("a", "b"), mk("b", "a")],
        };
        assert!(matches!(
            c.validate(),
            Err(ContentsError::CircularDependency(_))
        ));
    }

    #[test]
    fn depth_limit_enforced() {
        // chain of 7: op0 <- op1 <- ... <- op6
        let mut ops = vec![dist("op0", &[("x", 1)])];
        for i in 1..7 {
            ops.push(Operation {
                id: format!("op{i}"),
                depends_on: Some(format!("op{}", i - 1)),
                op: OperationType::DependentDistribution {
                    outcomes: [(
                        "x".to_string(),
                        [("y".to_string(), 1u64)].into_iter().collect(),
                    )]
                    .into_iter()
                    .collect(),
                },
            });
        }
        let c = Contents { operations: ops };
        assert_eq!(c.validate(), Err(ContentsError::DepthExceeded));
    }

    #[test]
    fn json_round_trip() {
        let c = Contents {
            operations: vec![
                dist("tier", &[("common", 7000), ("rare", 3000)]),
                Operation {
                    id: "quality".into(),
                    depends_on: None,
                    op: OperationType::Range {
                        range: RangeParams { min: 1, max: 100 },
                    },
                },
            ],
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Contents = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
