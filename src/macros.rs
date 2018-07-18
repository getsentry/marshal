/// Helper macro to implement string based serialization.
///
/// If a type implements `Display` then this automatically
/// implements a serializer for that type that dispatches
/// appropriately.
macro_rules! impl_str_ser {
    ($type:ty) => {
        impl ::serde::ser::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::ser::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }
    };
}

/// Helper macro to implement string based deserialization.
///
/// If a type implements `FromStr` then this automatically
/// implements a deserializer for that type that dispatches
/// appropriately.
macro_rules! impl_str_de {
    ($type:ty) => {
        impl<'de> ::serde::de::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::de::Deserializer<'de>,
            {
                <::std::borrow::Cow<str>>::deserialize(deserializer)?
                    .parse()
                    .map_err(::serde::de::Error::custom)
            }
        }
    };
}

/// Helper macro to implement string based serialization and deserialization.
///
/// If a type implements `FromStr` and `Display` then this automatically
/// implements a serializer/deserializer for that type that dispatches
/// appropriately.
macro_rules! impl_str_serde {
    ($type:ty) => {
        impl_str_ser!($type);
        impl_str_de!($type);
    };
}
