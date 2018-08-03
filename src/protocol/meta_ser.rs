use std::collections::BTreeMap;
use std::error;
use std::fmt;

use serde::ser::{
    Error, Impossible, Serialize, SerializeMap, SerializeSeq, SerializeStruct,
    SerializeStructVariant, SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
    Serializer,
};
use serde_json::{to_value, Value};

use super::meta::Annotated;
use super::serde::{CustomSerialize, ForwardSerialize};

/// Name of the marker struct used to serialize Annotated meta data.
const ANNOTATED_STRUCT: &str = "__annotated_struct__";
/// Name of the meta field.
const ANNOTATED_META: &str = "__annotated_meta__";
/// Name of the value field.
const ANNOTATED_VALUE: &str = "__annotated_value__";

/// Serializes an annotated meta data struct into the serializer.
pub fn serialize_annotated_meta<T, S, C>(
    annotated: &Annotated<T>,
    serializer: S,
    serialize: C,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: CustomSerialize<T>,
{
    let mut st = serializer.serialize_struct(ANNOTATED_STRUCT, 2)?;

    if !annotated.meta().is_empty() {
        st.serialize_field(ANNOTATED_META, annotated.meta())?;
    }

    if let Some(value) = annotated.value() {
        st.serialize_field(ANNOTATED_VALUE, &ForwardSerialize(value, serialize))?;
    }

    st.end()
}

#[derive(Debug, Default, Clone)]
pub struct MetaTree {
    meta: Option<Value>,
    children: BTreeMap<String, MetaTree>,
}

impl MetaTree {
    /// Creates a new meta tree.
    pub fn new() -> Self {
        MetaTree {
            meta: None,
            children: BTreeMap::new(),
        }
    }

    /// Returns `true` if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.meta.is_none() && self.children.is_empty()
    }

    /// Inserts a new child into the
    pub fn insert(&mut self, key: String, value: MetaTree) {
        self.children.insert(key, value);
    }
}

impl Serialize for MetaTree {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = self.meta.as_ref().map_or(0, |_| 1) + self.children.len();
        let mut map = serializer.serialize_map(Some(len))?;

        if let Some(ref meta) = self.meta {
            map.serialize_entry("", meta)?;
        }

        for (k, v) in &self.children {
            map.serialize_entry(k, v)?;
        }

        map.end()
    }
}

#[derive(Clone, Debug)]
pub struct MetaError {
    msg: String,
}

impl Error for MetaError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        MetaError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for MetaError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&self.msg)
    }
}

impl error::Error for MetaError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl PartialEq<str> for MetaError {
    fn eq(&self, other: &str) -> bool {
        self.msg == other
    }
}

struct MetaKeySerializer;

impl Serializer for MetaKeySerializer {
    type Ok = String;
    type Error = MetaError;

    type SerializeSeq = Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeMap = Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;
    type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(v.to_string())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(String::from_utf8_lossy(v).into_owned())
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(Error::custom("only string keys supported"))
    }
}

pub struct MetaSerializer;

impl Serializer for MetaSerializer {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    type SerializeSeq = SerializeSeqMeta;
    type SerializeTuple = SerializeTupleMeta;
    type SerializeTupleStruct = SerializeTupleStructMeta;
    type SerializeMap = SerializeMapMeta;
    type SerializeStruct = SerializeStructMeta;
    type SerializeTupleVariant = SerializeTupleVariantMeta;
    type SerializeStructVariant = SerializeStructVariantMeta;

    fn serialize_bool(self, _: bool) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_i8(self, _: i8) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_i16(self, _: i16) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_i32(self, _: i32) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_i64(self, _: i64) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_u8(self, _: u8) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_u16(self, _: u16) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_u32(self, _: u32) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_u64(self, _: u64) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_f32(self, _: f32) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_char(self, _: char) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_str(self, _: &str) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        Ok(value.serialize(self)?.map(|sub| {
            let mut tree = MetaTree::new();
            tree.insert(variant.to_string(), sub);
            tree
        }))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SerializeSeqMeta {
            map: BTreeMap::new(),
            index: 0,
        })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(SerializeTupleMeta {
            map: BTreeMap::new(),
            index: 0,
        })
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(SerializeTupleStructMeta {
            map: BTreeMap::new(),
            index: 0,
        })
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(SerializeTupleVariantMeta {
            map: BTreeMap::new(),
            name: variant,
            index: 0,
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(SerializeMapMeta {
            map: BTreeMap::new(),
            key: None,
        })
    }

    fn serialize_struct(
        self,
        name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(SerializeStructMeta {
            map: BTreeMap::new(),
            meta: None,
            annotated: name == ANNOTATED_STRUCT,
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(SerializeStructVariantMeta {
            map: BTreeMap::new(),
            name: variant,
        })
    }
}

pub struct SerializeSeqMeta {
    map: BTreeMap<String, MetaTree>,
    index: usize,
}

impl SerializeSeq for SerializeSeqMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if let Some(tree) = value.serialize(MetaSerializer)? {
            self.map.insert(self.index.to_string(), tree);
        }

        self.index += 1;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() {
            None
        } else {
            Some(MetaTree {
                meta: None,
                children: self.map,
            })
        })
    }
}

pub struct SerializeTupleMeta {
    map: BTreeMap<String, MetaTree>,
    index: usize,
}

impl SerializeTuple for SerializeTupleMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if let Some(tree) = value.serialize(MetaSerializer)? {
            self.map.insert(self.index.to_string(), tree);
        }

        self.index += 1;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() {
            None
        } else {
            Some(MetaTree {
                meta: None,
                children: self.map,
            })
        })
    }
}

pub struct SerializeTupleStructMeta {
    map: BTreeMap<String, MetaTree>,
    index: usize,
}

impl SerializeTupleStruct for SerializeTupleStructMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if let Some(tree) = value.serialize(MetaSerializer)? {
            self.map.insert(self.index.to_string(), tree);
        }

        self.index += 1;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() {
            None
        } else {
            Some(MetaTree {
                meta: None,
                children: self.map,
            })
        })
    }
}

pub struct SerializeTupleVariantMeta {
    map: BTreeMap<String, MetaTree>,
    name: &'static str,
    index: usize,
}

impl SerializeTupleVariant for SerializeTupleVariantMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if let Some(tree) = value.serialize(MetaSerializer)? {
            self.map.insert(self.index.to_string(), tree);
        }

        self.index += 1;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() {
            None
        } else {
            let subtree = MetaTree {
                meta: None,
                children: self.map,
            };

            let mut tree = MetaTree::new();
            tree.insert(self.name.to_string(), subtree);
            Some(tree)
        })
    }
}

pub struct SerializeMapMeta {
    map: BTreeMap<String, MetaTree>,
    key: Option<String>,
}

impl SerializeMap for SerializeMapMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_key<T: ?Sized>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if self.key.is_some() {
            return Err(Error::custom("serialize_key called twice"));
        }

        self.key = Some(key.serialize(MetaKeySerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::custom("serialize_value called without serialize_key"))?;

        if let Some(value) = value.serialize(MetaSerializer)? {
            self.map.insert(key, value);
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() {
            None
        } else {
            Some(MetaTree {
                meta: None,
                children: self.map,
            })
        })
    }
}

pub struct SerializeStructMeta {
    map: BTreeMap<String, MetaTree>,
    meta: Option<Value>,
    annotated: bool,
}

impl SerializeStruct for SerializeStructMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_field<T: ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if self.annotated {
            match key {
                ANNOTATED_META => {
                    let val = to_value(value).map_err(MetaError::custom)?;
                    self.meta = Some(val);
                }
                ANNOTATED_VALUE => {
                    if let Some(tree) = value.serialize(MetaSerializer)? {
                        self.map = tree.children;
                    }
                }
                _ => {
                    return Err(Error::custom("invalid annotated serialization field"));
                }
            }
        } else if let Some(tree) = value.serialize(MetaSerializer)? {
            self.map.insert(key.to_string(), tree);
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() && self.meta.is_none() {
            None
        } else {
            Some(MetaTree {
                meta: self.meta,
                children: self.map,
            })
        })
    }
}

pub struct SerializeStructVariantMeta {
    map: BTreeMap<String, MetaTree>,
    name: &'static str,
}

impl SerializeStructVariant for SerializeStructVariantMeta {
    type Ok = Option<MetaTree>;
    type Error = MetaError;

    fn serialize_field<T: ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        if let Some(tree) = value.serialize(MetaSerializer)? {
            self.map.insert(key.to_string(), tree);
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(if self.map.is_empty() {
            None
        } else {
            let subtree = MetaTree {
                meta: None,
                children: self.map,
            };

            let mut tree = MetaTree::new();
            tree.insert(self.name.to_string(), subtree);
            Some(tree)
        })
    }
}
