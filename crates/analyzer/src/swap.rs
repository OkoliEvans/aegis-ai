use guardian_core::IncomingTx;
use serde_json::Value;

const SWAP_HINTS: &[&str] = &[
    "swap",
    "swap_route",
    "execute_swap_operations",
    "offer_asset",
    "ask_asset",
    "amount_in",
    "amount_out",
    "minimum_receive",
    "belief_price",
    "max_spread",
    "slippage_tolerance",
];

#[derive(Debug, Clone)]
pub(crate) struct LocatedValue {
    pub path: String,
    pub value: Value,
}

pub(crate) fn looks_like_swap(tx: &IncomingTx) -> bool {
    if tx
        .function_name
        .as_deref()
        .is_some_and(|name| contains_swap_hint(name))
    {
        return true;
    }

    tx.contract_msg
        .as_ref()
        .is_some_and(contains_swap_structure)
}

pub(crate) fn extract_offer_amount(tx: &IncomingTx) -> Option<i128> {
    if tx.amount != "0" {
        if let Ok(amount) = tx.amount.parse::<i128>() {
            if amount > 0 {
                return Some(amount);
            }
        }
    }

    let msg = tx.contract_msg.as_ref()?;

    find_first_field(msg, &["offer_amount", "amount_in", "token_in_amount"])
        .and_then(|entry| parse_integer_amount(&entry.value))
        .or_else(|| {
            find_nested_amount(msg, "offer_asset")
                .or_else(|| find_nested_amount(msg, "offer_token"))
        })
}

pub(crate) fn extract_slippage_tolerance(tx: &IncomingTx) -> Option<(String, f64)> {
    let msg = tx.contract_msg.as_ref()?;
    let located = find_first_field(
        msg,
        &[
            "max_spread",
            "slippage_tolerance",
            "slippage",
            "max_slippage",
        ],
    )?;

    parse_fractional_ratio(&located.value).map(|ratio| (located.path, ratio))
}

pub(crate) fn parse_fractional_ratio(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => normalize_ratio(number.as_f64()?),
        Value::String(content) => parse_ratio_string(content),
        _ => None,
    }
}

fn parse_ratio_string(input: &str) -> Option<f64> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(raw) = trimmed
        .strip_suffix("bps")
        .or_else(|| trimmed.strip_suffix("bp"))
    {
        let amount = raw.trim().parse::<f64>().ok()?;
        return Some(amount / 10_000.0);
    }

    if let Some(raw) = trimmed.strip_suffix('%') {
        let amount = raw.trim().parse::<f64>().ok()?;
        return Some(amount / 100.0);
    }

    normalize_ratio(trimmed.parse::<f64>().ok()?)
}

fn normalize_ratio(value: f64) -> Option<f64> {
    if !(value.is_finite()) || value < 0.0 {
        return None;
    }

    if value <= 1.0 {
        Some(value)
    } else if value <= 100.0 {
        Some(value / 100.0)
    } else if value <= 10_000.0 && value.fract() == 0.0 {
        Some(value / 10_000.0)
    } else {
        None
    }
}

fn find_nested_amount(value: &Value, container_key: &str) -> Option<i128> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == container_key {
                    if let Some(amount) = child
                        .get("amount")
                        .and_then(parse_integer_amount)
                        .filter(|amount| *amount > 0)
                    {
                        return Some(amount);
                    }
                }

                if let Some(found) = find_nested_amount(child, container_key) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| find_nested_amount(child, container_key)),
        _ => None,
    }
}

fn contains_swap_structure(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, child)| contains_swap_hint(key) || contains_swap_structure(child)),
        Value::Array(items) => items.iter().any(contains_swap_structure),
        Value::String(content) => contains_swap_hint(content),
        _ => false,
    }
}

fn contains_swap_hint(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    SWAP_HINTS.iter().any(|hint| lower.contains(hint))
}

fn find_first_field(value: &Value, keys: &[&str]) -> Option<LocatedValue> {
    find_first_field_inner(value, "$", keys)
}

fn find_first_field_inner(value: &Value, path: &str, keys: &[&str]) -> Option<LocatedValue> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next_path = format!("{path}.{key}");
                if keys.iter().any(|candidate| candidate == key) {
                    return Some(LocatedValue {
                        path: next_path,
                        value: child.clone(),
                    });
                }

                if let Some(found) = find_first_field_inner(child, &next_path, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().enumerate().find_map(|(index, child)| {
            find_first_field_inner(child, &format!("{path}[{index}]"), keys)
        }),
        _ => None,
    }
}

fn parse_integer_amount(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) => number.as_i64().map(i128::from),
        Value::String(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return None;
            }

            if let Ok(parsed) = trimmed.parse::<i128>() {
                return Some(parsed);
            }

            let split_index = trimmed.find(|character: char| !character.is_ascii_digit())?;
            trimmed[..split_index].parse::<i128>().ok()
        }
        _ => None,
    }
}
