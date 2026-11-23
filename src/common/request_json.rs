// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rules of a JSON request body, after the syntax check: the reader gives the parsed value to the request type.
//!
//! - A structure accepts only an object. An array never fills the members of a structure in their order.
//! - `null` for a member keeps the zero value of its type: an empty text, zero, false, an empty list.
//! - When an object has the same member two times, the last value applies.
//!
//! The request types also refuse an unknown member (`#[serde(deny_unknown_fields)]`).

use serde::de::value::{MapDeserializer, SeqDeserializer};
use serde::de::{Deserializer, Error as _, IntoDeserializer, Unexpected, Visitor};
use serde::forward_to_deserialize_any;
use serde_json::{Error, Value};

/// One parsed JSON value, as the request types read it.
#[derive(Clone, Copy)]
pub struct RequestValue<'a>(pub &'a Value);

impl<'de> IntoDeserializer<'de, Error> for RequestValue<'de> {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

fn unexpected(value: &Value) -> Unexpected<'_> {
    match value {
        Value::Null => Unexpected::Unit,
        Value::Bool(flag) => Unexpected::Bool(*flag),
        Value::Number(_) => Unexpected::Other("number"),
        Value::String(text) => Unexpected::Str(text),
        Value::Array(_) => Unexpected::Seq,
        Value::Object(_) => Unexpected::Map,
    }
}

fn visit_items<'de, V: Visitor<'de>>(items: &'de [Value], visitor: V) -> Result<V::Value, Error> {
    let mut sequence = SeqDeserializer::new(items.iter().map(RequestValue));
    let value = visitor.visit_seq(&mut sequence)?;
    sequence.end()?;
    Ok(value)
}

fn visit_members<'de, V: Visitor<'de>>(
    members: &'de serde_json::Map<String, Value>,
    visitor: V,
) -> Result<V::Value, Error> {
    let mut map = MapDeserializer::new(members.iter().map(|(name, value)| (name.as_str(), RequestValue(value))));
    let value = visitor.visit_map(&mut map)?;
    map.end()?;
    Ok(value)
}

fn visit_no_members<'de, V: Visitor<'de>>(visitor: V) -> Result<V::Value, Error> {
    let mut map = MapDeserializer::new(std::iter::empty::<(&'de str, RequestValue<'de>)>());
    let value = visitor.visit_map(&mut map)?;
    map.end()?;
    Ok(value)
}

impl<'de> Deserializer<'de> for RequestValue<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(flag) => visitor.visit_bool(*flag),
            Value::Number(number) => {
                if let Some(value) = number.as_u64() {
                    visitor.visit_u64(value)
                } else if let Some(value) = number.as_i64() {
                    visitor.visit_i64(value)
                } else if let Some(value) = number.as_f64() {
                    visitor.visit_f64(value)
                } else {
                    Err(Error::invalid_type(Unexpected::Other("number"), &visitor))
                }
            }
            Value::String(text) => visitor.visit_borrowed_str(text),
            Value::Array(items) => visit_items(items, visitor),
            Value::Object(members) => visit_members(members, visitor),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Value::Object(members) => visit_members(members, visitor),
            Value::Null => visit_no_members(visitor),
            other => Err(Error::invalid_type(unexpected(other), &visitor)),
        }
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Object(members) => visit_members(members, visitor),
            Value::Null => visit_no_members(visitor),
            other => Err(Error::invalid_type(unexpected(other), &visitor)),
        }
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Array(items) => visit_items(items, visitor),
            Value::Null => visit_items(&[], visitor),
            other => Err(Error::invalid_type(unexpected(other), &visitor)),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_bool(false),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_i64(0),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_i64(visitor)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_i64(visitor)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_i64(visitor)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_u64(0),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_u64(visitor)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_u64(visitor)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_u64(visitor)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_f64(0.0),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_f64(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_borrowed_str(""),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.0.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        i128 u128 char bytes byte_buf unit unit_struct tuple tuple_struct identifier
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Tag {
        key: String,
        value: String,
    }

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields, default)]
    struct Request {
        instance: String,
        size: i64,
        count: u32,
        ratio: f64,
        #[serde(rename = "isPrefix")]
        is_prefix: bool,
        keys: Vec<String>,
        tags: Vec<Tag>,
        version: Option<String>,
    }

    fn read(text: &str) -> Result<Request, Error> {
        let value: Value = serde_json::from_str(text)?;
        Request::deserialize(RequestValue(&value))
    }

    #[test]
    fn an_object_fills_each_member() {
        let request = read(
            r#"{"instance":"a","size":-5,"count":7,"ratio":0.5,"isPrefix":true,"keys":["x","y"],"tags":[{"key":"k","value":"v"}],"version":"v1"}"#,
        )
        .unwrap();
        assert_eq!(
            request,
            Request {
                instance: "a".to_owned(),
                size: -5,
                count: 7,
                ratio: 0.5,
                is_prefix: true,
                keys: vec!["x".to_owned(), "y".to_owned()],
                tags: vec![Tag {
                    key: "k".to_owned(),
                    value: "v".to_owned()
                }],
                version: Some("v1".to_owned()),
            }
        );
    }

    #[test]
    fn an_array_never_fills_a_structure() {
        let error = read("[]").unwrap_err().to_string();
        assert!(error.contains("invalid type: sequence"), "{error}");
        assert!(read(r#"["a", 1, 2, 0.5, true, [], [], null]"#).is_err());
        let error = read(r#"{"tags":[["k","v"]]}"#).unwrap_err().to_string();
        assert!(error.contains("invalid type: sequence"), "{error}");
    }

    #[test]
    fn null_keeps_the_zero_value_of_each_member() {
        let request = read(
            r#"{"instance":null,"size":null,"count":null,"ratio":null,"isPrefix":null,"keys":null,"tags":null,"version":null}"#,
        )
        .unwrap();
        assert_eq!(request, Request::default());
        assert_eq!(read("null").unwrap(), Request::default());
    }

    #[test]
    fn the_last_value_of_a_repeated_member_applies() {
        assert_eq!(read(r#"{"instance":"a","instance":"b"}"#).unwrap().instance, "b");
    }

    #[test]
    fn an_unknown_member_or_a_wrong_type_is_an_error() {
        let error = read(r#"{"Instance":"a"}"#).unwrap_err().to_string();
        assert!(error.contains("unknown field `Instance`"), "{error}");
        let error = read(r#"{"instance":1}"#).unwrap_err().to_string();
        assert!(
            error.contains("invalid type: integer `1`, expected a string"),
            "{error}"
        );
        assert!(read(r#"{"count":-1}"#).is_err());
        assert!(read(r#"{"count":1.5}"#).is_err());
        assert!(read(r#"{"keys":"x"}"#).is_err());
        assert!(read(r#"{"tags":[{"key":"k","value":"v","other":1}]}"#).is_err());
        assert!(read(r#""text""#).is_err());
    }
}
