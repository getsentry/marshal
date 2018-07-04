use serde::de::{self, Deserialize, DeserializeSeed, Deserializer, Error, State, Visitor};
use std::fmt::{self, Display};
use std::rc::Rc;

/// Entry point. See crate documentation for an example.
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(TrackedDeserializer::new(deserializer))
}

fn state_with_parent_path<F: FnOnce(Rc<Path>) -> Rc<Path>>(state: &State, f: F) -> State {
    let mut rv = state.clone();
    let parent = state
        .get::<Rc<Path>>()
        .map(|x| x.clone())
        .unwrap_or_else(|| Rc::new(Path::Root));
    rv.set(f(parent));
    rv
}

/// Path to the current value in the input, like `dependencies.serde.typo1`.
pub enum Path {
    Root,
    Seq { parent: Rc<Path>, index: usize },
    Map { parent: Rc<Path>, key: String },
    Some { parent: Rc<Path> },
    NewtypeStruct { parent: Rc<Path> },
    NewtypeVariant { parent: Rc<Path> },
}

impl Display for Path {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        struct Parent<'a>(&'a Rc<Path>);

        impl<'a> Display for Parent<'a> {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
                match **self.0 {
                    Path::Root => Ok(()),
                    ref path => write!(formatter, "{}.", path),
                }
            }
        }

        match *self {
            Path::Root => formatter.write_str("."),
            Path::Seq { ref parent, index } => write!(formatter, "{}{}", Parent(parent), index),
            Path::Map {
                ref parent,
                ref key,
            } => write!(formatter, "{}{}", Parent(parent), key),
            Path::Some { ref parent }
            | Path::NewtypeStruct { ref parent }
            | Path::NewtypeVariant { ref parent } => write!(formatter, "{}?", Parent(parent)),
        }
    }
}

pub struct TrackedDeserializer<D> {
    de: D,
    state: State,
}

impl<D> TrackedDeserializer<D> {
    pub fn new(de: D) -> Self {
        let mut state = State::empty().clone();
        state.set(Rc::new(Path::Root));

        TrackedDeserializer {
            de: de,
            state: state,
        }
    }
}

impl<'de, D> Deserializer<'de> for TrackedDeserializer<D>
where
    D: Deserializer<'de>,
{
    type Error = D::Error;

    fn state(&self) -> &State {
        &self.state
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_any(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_bool(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_u8(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_u16(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_u32(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_u64(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_i8(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_i16(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_i32(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_i64(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_f32(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_f64(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_char(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_str(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_string(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_bytes(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_byte_buf(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_option(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_unit(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_unit_struct(name, TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_newtype_struct(name, TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_seq(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_tuple(len, TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_tuple_struct(name, len, TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_map(TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_struct(name, fields, TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_enum(name, variants, TrackedVisitor::new(visitor, &self.state))
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de.deserialize_ignored_any(visitor)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.de
            .deserialize_identifier(TrackedVisitor::new(visitor, &self.state))
    }
}

/// Wrapper that attaches context to a `Visitor`, `SeqAccess`, `EnumAccess` or
/// `VariantAccess`.
struct TrackedVisitor<X> {
    delegate: X,
    state: State,
}

impl<X> TrackedVisitor<X> {
    fn new(delegate: X, state: &State) -> Self {
        TrackedVisitor {
            delegate: delegate,
            state: state.clone(),
        }
    }
}

/// Forwarding impl to preserve context.
impl<'de, X> Visitor<'de> for TrackedVisitor<X>
where
    X: Visitor<'de>,
{
    type Value = X::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.delegate.expecting(formatter)
    }

    fn visit_bool<E: Error>(self, v: bool) -> Result<Self::Value, E> {
        self.delegate.visit_bool(v)
    }

    fn visit_i8<E: Error>(self, v: i8) -> Result<Self::Value, E> {
        self.delegate.visit_i8(v)
    }

    fn visit_i16<E: Error>(self, v: i16) -> Result<Self::Value, E> {
        self.delegate.visit_i16(v)
    }

    fn visit_i32<E: Error>(self, v: i32) -> Result<Self::Value, E> {
        self.delegate.visit_i32(v)
    }

    fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
        self.delegate.visit_i64(v)
    }

    fn visit_u8<E: Error>(self, v: u8) -> Result<Self::Value, E> {
        self.delegate.visit_u8(v)
    }

    fn visit_u16<E: Error>(self, v: u16) -> Result<Self::Value, E> {
        self.delegate.visit_u16(v)
    }

    fn visit_u32<E: Error>(self, v: u32) -> Result<Self::Value, E> {
        self.delegate.visit_u32(v)
    }

    fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
        self.delegate.visit_u64(v)
    }

    fn visit_f32<E: Error>(self, v: f32) -> Result<Self::Value, E> {
        self.delegate.visit_f32(v)
    }

    fn visit_f64<E: Error>(self, v: f64) -> Result<Self::Value, E> {
        self.delegate.visit_f64(v)
    }

    fn visit_char<E: Error>(self, v: char) -> Result<Self::Value, E> {
        self.delegate.visit_char(v)
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
        self.delegate.visit_str(v)
    }

    fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Self::Value, E> {
        self.delegate.visit_borrowed_str(v)
    }

    fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
        self.delegate.visit_string(v)
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        self.delegate.visit_unit()
    }

    fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
        self.delegate.visit_none()
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.delegate.visit_some(TrackedDeserializer {
            de: deserializer,
            state: state_with_parent_path(&self.state, |parent| Rc::new(Path::Some { parent })),
        })
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.delegate.visit_newtype_struct(TrackedDeserializer {
            de: deserializer,
            state: state_with_parent_path(&self.state, |parent| {
                Rc::new(Path::NewtypeStruct { parent })
            }),
        })
    }

    fn visit_seq<V: de::SeqAccess<'de>>(self, visitor: V) -> Result<Self::Value, V::Error> {
        self.delegate
            .visit_seq(SeqAccess::new(visitor, &self.state))
    }

    fn visit_map<V: de::MapAccess<'de>>(self, visitor: V) -> Result<Self::Value, V::Error> {
        self.delegate
            .visit_map(MapAccess::new(visitor, &self.state))
    }

    fn visit_enum<V: de::EnumAccess<'de>>(self, visitor: V) -> Result<Self::Value, V::Error> {
        self.delegate
            .visit_enum(TrackedVisitor::new(visitor, &self.state))
    }

    fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        self.delegate.visit_bytes(v)
    }

    fn visit_borrowed_bytes<E: Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.delegate.visit_borrowed_bytes(v)
    }

    fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.delegate.visit_byte_buf(v)
    }
}

/// Forwarding impl to preserve context.
impl<'de, X> de::EnumAccess<'de> for TrackedVisitor<X>
where
    X: de::EnumAccess<'de>,
{
    type Error = X::Error;
    type Variant = TrackedVisitor<X::Variant>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), X::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let path = &self.state;
        self.delegate
            .variant_seed(seed)
            .map(move |(v, vis)| (v, TrackedVisitor::new(vis, path)))
    }
}

/// Forwarding impl to preserve context.
impl<'de, X> de::VariantAccess<'de> for TrackedVisitor<X>
where
    X: de::VariantAccess<'de>,
{
    type Error = X::Error;

    fn unit_variant(self) -> Result<(), X::Error> {
        self.delegate.unit_variant()
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, X::Error>
    where
        T: DeserializeSeed<'de>,
    {
        let state = state_with_parent_path(&self.state, |parent| {
            Rc::new(Path::NewtypeVariant { parent })
        });
        self.delegate
            .newtype_variant_seed(TrackedSeed::new(seed, state))
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .tuple_variant(len, TrackedVisitor::new(visitor, &self.state))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .struct_variant(fields, TrackedVisitor::new(visitor, &self.state))
    }
}

/// Seed that saves the string into the given optional during `visit_str` and
/// `visit_string`.
struct CaptureKey<'a, X> {
    delegate: X,
    key: &'a mut Option<String>,
}

impl<'a, X> CaptureKey<'a, X> {
    fn new(delegate: X, key: &'a mut Option<String>) -> Self {
        CaptureKey {
            delegate: delegate,
            key: key,
        }
    }
}

/// Forwarding impl.
impl<'a, 'de, X> DeserializeSeed<'de> for CaptureKey<'a, X>
where
    X: DeserializeSeed<'de>,
{
    type Value = X::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<X::Value, D::Error> {
        self.delegate
            .deserialize(CaptureKey::new(deserializer, self.key))
    }
}

/// Forwarding impl.
impl<'a, 'de, X> Deserializer<'de> for CaptureKey<'a, X>
where
    X: Deserializer<'de>,
{
    type Error = X::Error;

    fn state(&self) -> &State {
        self.delegate.state()
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_any(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_bool(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_u8(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_u16(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_u32(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_u64(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_i8(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_i16(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_i32(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_i64(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_f32(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_f64(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_char(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_str(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_string(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_bytes(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_byte_buf(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_option(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_unit(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_unit_struct(name, CaptureKey::new(visitor, self.key))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_newtype_struct(name, CaptureKey::new(visitor, self.key))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_seq(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_tuple(len, CaptureKey::new(visitor, self.key))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_tuple_struct(name, len, CaptureKey::new(visitor, self.key))
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_map(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_struct(name, fields, CaptureKey::new(visitor, self.key))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_enum(name, variants, CaptureKey::new(visitor, self.key))
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_ignored_any(CaptureKey::new(visitor, self.key))
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, X::Error> {
        self.delegate
            .deserialize_identifier(CaptureKey::new(visitor, self.key))
    }
}

/// Forwarding impl except `visit_str` and `visit_string` which save the string.
impl<'a, 'de, X> Visitor<'de> for CaptureKey<'a, X>
where
    X: Visitor<'de>,
{
    type Value = X::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.delegate.expecting(formatter)
    }

    fn visit_bool<E: Error>(self, v: bool) -> Result<Self::Value, E> {
        self.delegate.visit_bool(v)
    }

    fn visit_i8<E: Error>(self, v: i8) -> Result<Self::Value, E> {
        self.delegate.visit_i8(v)
    }

    fn visit_i16<E: Error>(self, v: i16) -> Result<Self::Value, E> {
        self.delegate.visit_i16(v)
    }

    fn visit_i32<E: Error>(self, v: i32) -> Result<Self::Value, E> {
        self.delegate.visit_i32(v)
    }

    fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
        self.delegate.visit_i64(v)
    }

    fn visit_u8<E: Error>(self, v: u8) -> Result<Self::Value, E> {
        self.delegate.visit_u8(v)
    }

    fn visit_u16<E: Error>(self, v: u16) -> Result<Self::Value, E> {
        self.delegate.visit_u16(v)
    }

    fn visit_u32<E: Error>(self, v: u32) -> Result<Self::Value, E> {
        self.delegate.visit_u32(v)
    }

    fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
        self.delegate.visit_u64(v)
    }

    fn visit_f32<E: Error>(self, v: f32) -> Result<Self::Value, E> {
        self.delegate.visit_f32(v)
    }

    fn visit_f64<E: Error>(self, v: f64) -> Result<Self::Value, E> {
        self.delegate.visit_f64(v)
    }

    fn visit_char<E: Error>(self, v: char) -> Result<Self::Value, E> {
        self.delegate.visit_char(v)
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
        *self.key = Some(v.to_owned());
        self.delegate.visit_str(v)
    }

    fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Self::Value, E> {
        *self.key = Some(v.to_owned());
        self.delegate.visit_borrowed_str(v)
    }

    fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
        *self.key = Some(v.clone());
        self.delegate.visit_string(v)
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        self.delegate.visit_unit()
    }

    fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
        self.delegate.visit_none()
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.delegate.visit_some(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.delegate.visit_newtype_struct(deserializer)
    }

    fn visit_seq<V: de::SeqAccess<'de>>(self, visitor: V) -> Result<Self::Value, V::Error> {
        self.delegate.visit_seq(visitor)
    }

    fn visit_map<V: de::MapAccess<'de>>(self, visitor: V) -> Result<Self::Value, V::Error> {
        self.delegate.visit_map(visitor)
    }

    fn visit_enum<V: de::EnumAccess<'de>>(self, visitor: V) -> Result<Self::Value, V::Error> {
        self.delegate.visit_enum(visitor)
    }

    fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        self.delegate.visit_bytes(v)
    }

    fn visit_borrowed_bytes<E: Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.delegate.visit_borrowed_bytes(v)
    }

    fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.delegate.visit_byte_buf(v)
    }
}

/// Seed used for map values, sequence elements and newtype variants to track
/// their path.
struct TrackedSeed<X> {
    seed: X,
    state: State,
}

impl<X> TrackedSeed<X> {
    fn new(seed: X, state: State) -> Self {
        TrackedSeed {
            seed: seed,
            state: state,
        }
    }
}

impl<'de, X> DeserializeSeed<'de> for TrackedSeed<X>
where
    X: DeserializeSeed<'de>,
{
    type Value = X::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<X::Value, D::Error> {
        self.seed.deserialize(TrackedDeserializer {
            de: deserializer,
            state: self.state.clone(),
        })
    }
}

/// Seq visitor that tracks the index of its elements.
struct SeqAccess<X> {
    delegate: X,
    state: State,
    index: usize,
}

impl<X> SeqAccess<X> {
    fn new(delegate: X, state: &State) -> Self {
        SeqAccess {
            delegate: delegate,
            state: state.clone(),
            index: 0,
        }
    }
}

/// Forwarding impl to preserve context.
impl<'de, X> de::SeqAccess<'de> for SeqAccess<X>
where
    X: de::SeqAccess<'de>,
{
    type Error = X::Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, X::Error>
    where
        T: DeserializeSeed<'de>,
    {
        let state = state_with_parent_path(&self.state, |parent| {
            Rc::new(Path::Seq {
                parent,
                index: self.index,
            })
        });
        self.index += 1;
        self.delegate
            .next_element_seed(TrackedSeed::new(seed, state))
    }

    fn size_hint(&self) -> Option<usize> {
        self.delegate.size_hint()
    }
}

/// Map visitor that captures the string value of its keys and uses that to
/// track the path to its values.
struct MapAccess<X> {
    delegate: X,
    state: State,
    key: Option<String>,
}

impl<X> MapAccess<X> {
    fn new(delegate: X, state: &State) -> Self {
        MapAccess {
            delegate: delegate,
            state: state.clone(),
            key: None,
        }
    }

    fn key<E: Error>(&mut self) -> Result<String, E> {
        self.key.take().ok_or_else(|| E::custom("non-string key"))
    }
}

impl<'de, X> de::MapAccess<'de> for MapAccess<X>
where
    X: de::MapAccess<'de>,
{
    type Error = X::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, X::Error> {
        self.delegate
            .next_key_seed(CaptureKey::new(seed, &mut self.key))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, X::Error> {
        let key = self.key()?;
        let state =
            state_with_parent_path(&self.state, |parent| Rc::new(Path::Map { parent, key }));
        self.delegate.next_value_seed(TrackedSeed::new(seed, state))
    }

    fn size_hint(&self) -> Option<usize> {
        self.delegate.size_hint()
    }
}
