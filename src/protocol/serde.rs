//! Defines the `CustomDeserialize` trait.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

/// Provides a custom `serde::Deserialize` implementation for a type.
pub trait CustomDeserialize<'de, T> {
    /// Deserialize the value from the given Serde deserializer.
    fn deserialize<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>;
}

/// Implementation of `CustomDeserialize` that uses the type's `Deserialize` implementation.
#[derive(Debug)]
pub struct DefaultDeserialize<T>(PhantomData<T>);

impl<T> Default for DefaultDeserialize<T> {
    fn default() -> Self {
        DefaultDeserialize(PhantomData)
    }
}

impl<'de, T: Deserialize<'de>> CustomDeserialize<'de, T> for DefaultDeserialize<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
        T::deserialize(deserializer)
    }
}

/// Provides a custom `serde::Serialize` implementation for a type.
pub trait CustomSerialize<T> {
    /// Serialize this value into the given Serde serializer.
    fn serialize<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

/// Implementation of `CustomSerialize` that uses the type's `Serialize` implementation.
#[derive(Debug)]
pub struct DefaultSerialize<T>(PhantomData<T>);

impl<T> Default for DefaultSerialize<T> {
    fn default() -> Self {
        DefaultSerialize(PhantomData)
    }
}

impl<T: Serialize> CustomSerialize<T> for DefaultSerialize<T> {
    fn serialize<S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }
}

pub struct ForwardSerialize<'a, T: 'a, C>(pub &'a T, pub C);

impl<'a, T: 'a, C> Serialize for ForwardSerialize<'a, T, C>
where
    C: CustomSerialize<T>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        C::serialize(self.0, serializer)
    }
}
