//! Various utilities, like serialization and deserialization helpers.

use super::common::{Array, Map, Values};
use super::meta::{should_serialize_meta, Annotated};

pub fn skip_if<T, F>(annotated: &Annotated<T>, predicate: F) -> bool
where
    F: FnOnce(&T) -> bool,
{
    // There are two serialization modes:
    //  1. Data serialization (default). If there is meta data attached, we must not skip this
    //     value, as otherwise deserialization in the next relay will not pick it up later.
    //     Otherwise, we can safely execute the predicate.
    //  2. Meta serialization. We can never skip, and the MetaTreeSerializer will recursively prune
    //     empty meta nodes.

    !should_serialize_meta()
        && annotated.meta().is_empty()
        && annotated.value().map_or(true, predicate)
}

pub fn is_false(annotated: &Annotated<bool>) -> bool {
    skip_if(annotated, |b| !b)
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
