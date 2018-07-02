use chunk::Meta;

pub struct Annotated<T> {
    value: T,
    meta: Meta,
}

impl<T> Annotated<T> {
    pub fn new(value: T) -> Annotated<T> {
        Self::new_with_meta(value, Default::default())
    }

    pub fn new_with_meta(value: T, meta: Meta) -> Annotated<T> {
        Annotated {
            value: value,
            meta: meta,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    pub fn into_value(self) -> T {
        self.value
    }
}
