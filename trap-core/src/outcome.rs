//! Outcome evaluation: deterministically maps combined randomness through
//! the contents' operations. Spec §6.2–6.3, §8.
//!
//! Operations are evaluated in declaration order. A dependent operation's
//! parent must be declared (and therefore evaluated) before it.

use crate::crypto::hash::{derive_operation_random, reduce_mod};
use crate::types::contents::{
    Contents, ContentsError, OperationType, Outcome, OutcomeValue, RangeParams,
};
use indexmap::IndexMap;

fn pick_weighted(table: &IndexMap<String, u64>, derived: &[u8; 32]) -> Option<String> {
    let total: u64 = table.values().sum();
    if total == 0 {
        return None;
    }
    let mut r = reduce_mod(derived, total);
    for (name, weight) in table {
        if r < *weight {
            return Some(name.clone());
        }
        r -= weight;
    }
    None // unreachable when weights sum to total
}

fn pick_range(range: &RangeParams, derived: &[u8; 32]) -> i64 {
    let span = (range.max as i128 - range.min as i128 + 1) as u64;
    range.min.wrapping_add(reduce_mod(derived, span) as i64)
}

fn parent_key(value: &OutcomeValue) -> String {
    match value {
        OutcomeValue::Selected(s) => s.clone(),
        OutcomeValue::Number(n) => n.to_string(),
    }
}

/// Evaluate all operations against the combined randomness.
///
/// Each operation's random value is derived independently:
/// `SHA256(combined_randomness || operation_id)`.
pub fn evaluate(contents: &Contents, combined: &[u8; 32]) -> Result<Outcome, ContentsError> {
    contents.validate()?;
    let mut results: IndexMap<String, OutcomeValue> = IndexMap::new();

    for op in &contents.operations {
        let derived = derive_operation_random(combined, &op.id);
        let value = match &op.op {
            OperationType::Distribution { outcomes } => OutcomeValue::Selected(
                pick_weighted(outcomes, &derived)
                    .ok_or_else(|| ContentsError::ZeroWeights(op.id.clone()))?,
            ),
            OperationType::Range { range } => OutcomeValue::Number(pick_range(range, &derived)),
            OperationType::DependentDistribution { outcomes } => {
                let dep = op.depends_on.as_ref().expect("validated");
                let parent = results
                    .get(dep)
                    .ok_or_else(|| ContentsError::UnknownDependency(op.id.clone(), dep.clone()))?;
                let key = parent_key(parent);
                let table = outcomes.get(&key).ok_or_else(|| {
                    ContentsError::MissingDependencyBranch(op.id.clone(), key.clone())
                })?;
                OutcomeValue::Selected(
                    pick_weighted(table, &derived)
                        .ok_or_else(|| ContentsError::ZeroWeights(op.id.clone()))?,
                )
            }
            OperationType::DependentRange { ranges } => {
                let dep = op.depends_on.as_ref().expect("validated");
                let parent = results
                    .get(dep)
                    .ok_or_else(|| ContentsError::UnknownDependency(op.id.clone(), dep.clone()))?;
                let key = parent_key(parent);
                let range = ranges.get(&key).ok_or_else(|| {
                    ContentsError::MissingDependencyBranch(op.id.clone(), key.clone())
                })?;
                OutcomeValue::Number(pick_range(range, &derived))
            }
        };
        results.insert(op.id.clone(), value);
    }

    Ok(Outcome { results })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::contents::Operation;

    fn contents_tier_item_quality() -> Contents {
        Contents {
            operations: vec![
                Operation {
                    id: "tier".into(),
                    depends_on: None,
                    op: OperationType::Distribution {
                        outcomes: [
                            ("common".to_string(), 7000u64),
                            ("rare".to_string(), 2500),
                            ("epic".to_string(), 500),
                        ]
                        .into_iter()
                        .collect(),
                    },
                },
                Operation {
                    id: "item".into(),
                    depends_on: Some("tier".into()),
                    op: OperationType::DependentDistribution {
                        outcomes: [
                            (
                                "common".to_string(),
                                [("item_a".to_string(), 50u64), ("item_b".to_string(), 50)]
                                    .into_iter()
                                    .collect(),
                            ),
                            (
                                "rare".to_string(),
                                [("item_d".to_string(), 100u64)].into_iter().collect(),
                            ),
                            (
                                "epic".to_string(),
                                [("item_g".to_string(), 100u64)].into_iter().collect(),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    },
                },
                Operation {
                    id: "quality".into(),
                    depends_on: Some("tier".into()),
                    op: OperationType::DependentRange {
                        ranges: [
                            ("common".to_string(), RangeParams { min: 1, max: 50 }),
                            ("rare".to_string(), RangeParams { min: 40, max: 80 }),
                            ("epic".to_string(), RangeParams { min: 75, max: 100 }),
                        ]
                        .into_iter()
                        .collect(),
                    },
                },
            ],
        }
    }

    #[test]
    fn p4_deterministic_for_same_randomness() {
        let c = contents_tier_item_quality();
        let a = evaluate(&c, &[5; 32]).unwrap();
        let b = evaluate(&c, &[5; 32]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn r4_dependent_op_uses_parent_branch() {
        let c = contents_tier_item_quality();
        for seed in 0u8..32 {
            let o = evaluate(&c, &[seed; 32]).unwrap();
            let tier = match &o.results["tier"] {
                OutcomeValue::Selected(s) => s.clone(),
                _ => panic!("tier should be a selection"),
            };
            let item = match &o.results["item"] {
                OutcomeValue::Selected(s) => s.clone(),
                _ => panic!("item should be a selection"),
            };
            // item must come from the tier's table
            let valid = match tier.as_str() {
                "common" => item == "item_a" || item == "item_b",
                "rare" => item == "item_d",
                "epic" => item == "item_g",
                _ => false,
            };
            assert!(valid, "tier={tier} item={item}");
            // quality must be in the tier's range
            let q = match &o.results["quality"] {
                OutcomeValue::Number(n) => *n,
                _ => panic!("quality should be a number"),
            };
            let in_range = match tier.as_str() {
                "common" => (1..=50).contains(&q),
                "rare" => (40..=80).contains(&q),
                "epic" => (75..=100).contains(&q),
                _ => false,
            };
            assert!(in_range, "tier={tier} quality={q}");
        }
    }

    #[test]
    fn r2_distribution_respects_weights() {
        // 90/10 split over many trials lands near 90% (loose tolerance).
        let c = Contents {
            operations: vec![Operation {
                id: "x".into(),
                depends_on: None,
                op: OperationType::Distribution {
                    outcomes: [("a".to_string(), 9000u64), ("b".to_string(), 1000)]
                        .into_iter()
                        .collect(),
                },
            }],
        };
        let trials = 10_000;
        let mut a_count = 0;
        for i in 0..trials {
            let mut combined = [0u8; 32];
            combined[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let o = evaluate(&c, &combined).unwrap();
            if o.results["x"] == OutcomeValue::Selected("a".into()) {
                a_count += 1;
            }
        }
        let frac = a_count as f64 / trials as f64;
        assert!((0.88..=0.92).contains(&frac), "frac={frac}");
    }

    #[test]
    fn r3_range_stays_in_bounds() {
        let c = Contents {
            operations: vec![Operation {
                id: "r".into(),
                depends_on: None,
                op: OperationType::Range {
                    range: RangeParams { min: 10, max: 20 },
                },
            }],
        };
        for i in 0u64..1000 {
            let mut combined = [0u8; 32];
            combined[..8].copy_from_slice(&i.to_be_bytes());
            match evaluate(&c, &combined).unwrap().results["r"] {
                OutcomeValue::Number(n) => assert!((10..=20).contains(&n)),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn r5_full_width_range_errors_not_panics() {
        // A near-full-width range used to overflow pick_range's u64 span to
        // zero and panic in reduce_mod. evaluate must now return a clean
        // error on this attacker-supplied input instead of crashing.
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
        assert!(matches!(
            evaluate(&c, &[0; 32]),
            Err(ContentsError::RangeTooWide(_))
        ));
    }
}
