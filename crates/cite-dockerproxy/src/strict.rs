use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

// Go's decoder merges duplicate keys and matches names case-insensitively, so neither may exist.
pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Strict.deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(value)
}

struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a json value without duplicate keys")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number is not finite"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Strict)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !key.is_ascii() {
                return Err(de::Error::custom("object keys must be ascii"));
            }
            if !seen.insert(key.to_ascii_lowercase()) {
                return Err(de::Error::custom("duplicate object key"));
            }
            out.insert(key, map.next_value_seed(Strict)?);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn plain_documents_round_trip() {
        let v = parse(br#"{"A":1,"b":[true,null,"x",{"C":2.5}]}"#).unwrap();
        assert_eq!(v["b"][3]["C"], 2.5);
        assert_eq!(v["A"], 1);
    }

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        assert!(parse(br#"{"HostConfig":{},"HostConfig":{}}"#).is_err());
        assert!(parse(br#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(parse(br#"{"a":[{"b":1,"b":2}]}"#).is_err());
    }

    #[test]
    fn case_variants_and_escaped_duplicates_are_rejected() {
        assert!(parse(br#"{"HostConfig":{},"HOSTCONFIG":{}}"#).is_err());
        assert!(parse(br#"{"Privileged":true,"Privileged":false}"#).is_err());
    }

    #[test]
    fn non_ascii_keys_and_trailing_data_are_rejected() {
        assert!(parse("{\"Hos\u{0131}tConfig\":{}}".as_bytes()).is_err());
        assert!(parse(br#"{"a":1} {"b":2}"#).is_err());
        assert!(parse(br#"{"a":1}x"#).is_err());
        assert!(parse(b"").is_err());
    }
}
