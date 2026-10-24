//! A deliberately small JSON Schema subset for tool arguments.
//!
//! Supported keywords: `type` (object, string, integer, number, boolean,
//! array), `properties`, `required`, `additionalProperties: false`, `enum`,
//! `minimum`, `maximum`, `minLength`, `maxLength`, `items`, `maxItems`, and
//! `default` (applied to missing top-level properties). Manifests that use any
//! other keyword are rejected at load time, so a schema can never look stricter
//! than what is actually enforced.

use serde_json::{Map, Value};

const KEYWORDS: [&str; 13] = [
    "type", "properties", "required", "additionalProperties", "enum", "minimum", "maximum", "minLength",
    "maxLength", "items", "maxItems", "default", "description",
];

/// Checks that a schema only uses supported keywords.
pub fn check_schema(schema: &Value, at: &str) -> Result<(), String> {
    let obj = schema.as_object().ok_or_else(|| format!("{at}: schema must be an object"))?;
    for key in obj.keys() {
        if !KEYWORDS.contains(&key.as_str()) {
            return Err(format!("{at}: unsupported schema keyword '{key}'"));
        }
    }
    match obj.get("type").and_then(Value::as_str) {
        Some("object" | "string" | "integer" | "number" | "boolean" | "array") => {}
        other => return Err(format!("{at}: unsupported type {other:?}")),
    }
    if let Some(props) = obj.get("properties") {
        let props = props.as_object().ok_or_else(|| format!("{at}: properties must be an object"))?;
        for (name, sub) in props {
            check_schema(sub, &format!("{at}.{name}"))?;
        }
    }
    if let Some(items) = obj.get("items") {
        check_schema(items, &format!("{at}[]"))?;
    }
    if let Some(ap) = obj.get("additionalProperties") {
        if ap != &Value::Bool(false) {
            return Err(format!("{at}: additionalProperties may only be false"));
        }
    }
    Ok(())
}

/// Validates `args` against `schema`, returning the args with defaults filled in.
pub fn validate(schema: &Value, args: Value) -> Result<Value, String> {
    let args = if args.is_null() { Value::Object(Map::new()) } else { args };
    let mut args = args;
    if let (Some(props), Some(obj)) = (schema.get("properties").and_then(Value::as_object), args.as_object_mut()) {
        for (name, sub) in props {
            if !obj.contains_key(name) {
                if let Some(default) = sub.get("default") {
                    obj.insert(name.clone(), default.clone());
                }
            }
        }
    }
    check_value(schema, &args, "args")?;
    Ok(args)
}

fn check_value(schema: &Value, value: &Value, at: &str) -> Result<(), String> {
    let ty = schema.get("type").and_then(Value::as_str).unwrap_or("object");
    let type_ok = match ty {
        "object" => value.is_object(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        _ => false,
    };
    if !type_ok {
        return Err(format!("{at} must be of type {ty}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            let list: Vec<String> = allowed.iter().map(|v| v.to_string()).collect();
            return Err(format!("{at} must be one of {}", list.join(", ")));
        }
    }
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
            if n < min {
                return Err(format!("{at} must be >= {min}"));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
            if n > max {
                return Err(format!("{at} must be <= {max}"));
            }
        }
    }
    if let Some(s) = value.as_str() {
        let len = s.chars().count() as u64;
        if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
            if len < min {
                return Err(format!("{at} must be at least {min} characters"));
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
            if len > max {
                return Err(format!("{at} must be at most {max} characters"));
            }
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
            if items.len() as u64 > max {
                return Err(format!("{at} may contain at most {max} items"));
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (i, item) in items.iter().enumerate() {
                check_value(item_schema, item, &format!("{at}[{i}]"))?;
            }
        }
    }
    if let Some(obj) = value.as_object() {
        let props = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !obj.contains_key(name) {
                    return Err(format!("{at}.{name} is required"));
                }
            }
        }
        for (name, v) in obj {
            match props.and_then(|p| p.get(name)) {
                Some(sub) => check_value(sub, v, &format!("{at}.{name}"))?,
                None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    return Err(format!("{at}.{name} is not a recognized argument"));
                }
                None => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn manifest_property_order_is_kept() {
        // The UI builds tool forms in this order, so it must match the manifest
        // (needs serde_json's `preserve_order` feature).
        let schema: Value = serde_json::from_str(r#"{"properties":{"startTime":{},"endTime":{},"cpuThresholdPercent":{}}}"#).unwrap();
        let keys: Vec<&str> = schema["properties"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["startTime", "endTime", "cpuThresholdPercent"]);
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["channel"],
            "properties": {
                "channel": { "type": "string", "enum": ["Application", "System"] },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 25 },
                "source": { "type": "string", "maxLength": 5 },
                "names": { "type": "array", "maxItems": 2, "items": { "type": "string" } }
            }
        })
    }

    #[test]
    fn applies_defaults_and_accepts_valid_args() {
        let out = validate(&schema(), json!({ "channel": "System" })).unwrap();
        assert_eq!(out, json!({ "channel": "System", "limit": 25 }));
        assert!(check_schema(&schema(), "t").is_ok());
    }

    #[test]
    fn rejects_bad_args() {
        for (args, needle) in [
            (json!({}), "required"),
            (json!({ "channel": "Security" }), "one of"),
            (json!({ "channel": "System", "limit": 0 }), ">="),
            (json!({ "channel": "System", "limit": 2.5 }), "integer"),
            (json!({ "channel": "System", "source": "toolong" }), "at most"),
            (json!({ "channel": "System", "names": ["a", "b", "c"] }), "at most 2"),
            (json!({ "channel": "System", "names": [1] }), "string"),
            (json!({ "channel": "System", "extra": true }), "not a recognized"),
            (json!("nope"), "object"),
        ] {
            let err = validate(&schema(), args.clone()).unwrap_err();
            assert!(err.contains(needle), "{args} -> {err}");
        }
    }

    #[test]
    fn rejects_unsupported_keywords() {
        let err = check_schema(&json!({ "type": "object", "properties": { "x": { "type": "string", "pattern": ".*" } } }), "t").unwrap_err();
        assert!(err.contains("pattern"));
    }
}
