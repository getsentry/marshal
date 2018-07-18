//! Various utilities, like serialization and deserialization helpers.

use super::common::{Array, Map, Values};
use super::meta::{should_serialize_meta, Annotated};

fn skip_if<T, F>(annotated: &Annotated<T>, predicate: F) -> bool
where
    F: FnOnce(&T) -> bool,
{
    // Always serialize meta data. The MetaTreeSerializer will automatically remove empty nodes.
    !should_serialize_meta() && annotated.value().map_or(false, predicate)
}

pub fn is_none<T>(annotated: &Annotated<Option<T>>) -> bool {
    skip_if(annotated, Option::is_none)
}

pub fn is_empty_values<T>(annotated: &Annotated<Values<T>>) -> bool {
    skip_if(annotated, Values::is_empty)
}

pub fn is_empty_array<V>(annotated: &Annotated<Array<V>>) -> bool {
    skip_if(annotated, Array::is_empty)
}

pub fn is_empty_map<V>(annotated: &Annotated<Map<V>>) -> bool {
    skip_if(annotated, Map::is_empty)
}
