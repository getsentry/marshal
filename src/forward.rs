use serde::ser::{
    Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant, Serializer,
};

pub struct ForwardMapSerializer<'a, M: 'a>(pub &'a mut M);

impl<'a, M> Serializer for ForwardMapSerializer<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    type SerializeSeq = SerializeSeqAsMap<'a, M>;
    type SerializeTuple = SerializeTupleAsMap<'a, M>;
    type SerializeTupleStruct = SerializeTupleStructAsMap<'a, M>;
    type SerializeMap = SerializeMapForward<'a, M>;
    type SerializeStruct = SerializeStructAsMap<'a, M>;
    type SerializeTupleVariant = SerializeTupleVariantAsMap<'a, M>;
    type SerializeStructVariant = SerializeStructVariantAsMap<'a, M>;

    fn serialize_bool(self, _: bool) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_i8(self, _: i8) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_i16(self, _: i16) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_i32(self, _: i32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_i64(self, _: i64) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_u8(self, _: u8) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_u16(self, _: u16) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_u32(self, _: u32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_u64(self, _: u64) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_f32(self, _: f32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_char(self, _: char) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_str(self, _: &str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(())
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
        self.0.serialize_key(variant)?;
        self.0.serialize_value(value)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SerializeSeqAsMap(self.0, 0))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(SerializeTupleAsMap(self.0, 0))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(SerializeTupleStructAsMap(self.0, 0))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.0.serialize_key(variant)?;
        Ok(SerializeTupleVariantAsMap(self.0, 0))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(SerializeMapForward(self.0))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(SerializeStructAsMap(self.0))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.0.serialize_key(variant)?;
        Ok(SerializeStructVariantAsMap(self.0))
    }
}

pub struct SerializeSeqAsMap<'a, M: 'a>(&'a mut M, usize);

impl<'a, M> SerializeSeq for SerializeSeqAsMap<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        let key = self.1.to_string();
        self.1 += 1;
        self.0.serialize_entry(&key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub struct SerializeTupleAsMap<'a, M: 'a>(&'a mut M, usize);

impl<'a, M> SerializeTuple for SerializeTupleAsMap<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        let key = self.1.to_string();
        self.1 += 1;
        self.0.serialize_entry(&key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub struct SerializeTupleStructAsMap<'a, M: 'a>(&'a mut M, usize);

impl<'a, M> SerializeTupleStruct for SerializeTupleStructAsMap<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        let key = self.1.to_string();
        self.1 += 1;
        self.0.serialize_entry(&key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub struct SerializeTupleVariantAsMap<'a, M: 'a>(&'a mut M, usize);

impl<'a, M> SerializeTupleVariant for SerializeTupleVariantAsMap<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        let key = self.1.to_string();
        self.1 += 1;
        self.0.serialize_entry(&key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub struct SerializeMapForward<'a, M: 'a>(&'a mut M);

impl<'a, M> SerializeMap for SerializeMapForward<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_key<T: ?Sized>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        self.0.serialize_key(key)
    }

    fn serialize_value<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        self.0.serialize_value(value)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct SerializeStructAsMap<'a, M: 'a>(&'a mut M);

impl<'a, M> SerializeStruct for SerializeStructAsMap<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_field<T: ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        self.0.serialize_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub struct SerializeStructVariantAsMap<'a, M: 'a>(&'a mut M);

impl<'a, M> SerializeStructVariant for SerializeStructVariantAsMap<'a, M>
where
    M: SerializeMap + 'a,
{
    type Ok = ();
    type Error = M::Error;

    fn serialize_field<T: ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        self.0.serialize_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod forward_tests {
    use super::*;
    use serde_json;
    use std::collections::BTreeMap;

    fn serialize<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
        let mut vec = Vec::new();

        {
            let mut serializer = serde_json::Serializer::new(&mut vec);
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("foo", "bar")?;
            value.serialize(ForwardMapSerializer(&mut map))?;
            SerializeMap::end(map)?;
        }

        Ok(String::from_utf8(vec).unwrap())
    }

    #[test]
    fn test_basic_types() {
        let json = r#"{"foo":"bar"}"#;
        assert_eq!(json, serialize(&()).unwrap());
        assert_eq!(json, serialize(&1).unwrap());
        assert_eq!(json, serialize(&1.0).unwrap());
        assert_eq!(json, serialize(&Some("bla")).unwrap());
    }

    #[test]
    fn test_seq() {
        assert_eq!(r#"{"foo":"bar","0":1,"1":2}"#, serialize(&[1, 2]).unwrap());
    }

    #[test]
    fn test_tuple() {
        assert_eq!(r#"{"foo":"bar","0":1,"1":2}"#, serialize(&(1, 2)).unwrap());
    }

    #[test]
    fn test_map() {
        let mut map = BTreeMap::new();
        map.insert("it", "works");
        map.insert("really", "well");
        assert_eq!(
            r#"{"foo":"bar","it":"works","really":"well"}"#,
            serialize(&map).unwrap()
        );
    }

    #[test]
    fn test_struct() {
        #[derive(Debug, Serialize)]
        struct Test {
            it: &'static str,
            really: &'static str,
        }

        let test = Test {
            it: "works",
            really: "well",
        };

        assert_eq!(
            r#"{"foo":"bar","it":"works","really":"well"}"#,
            serialize(&test).unwrap()
        );
    }

    #[test]
    fn test_enum() {
        #[derive(Debug, Serialize)]
        enum Test {
            A,
            B(i32),
            C(i32, i32),
            D { e: i32 },
        }

        assert_eq!(r#"{"foo":"bar"}"#, serialize(&Test::A).unwrap());
        assert_eq!(r#"{"foo":"bar","B":1}"#, serialize(&Test::B(1)).unwrap());
        // TODO: This is invalid
        assert_eq!(
            r#"{"foo":"bar","C","0":1,"1":2}"#,
            serialize(&Test::C(1, 2)).unwrap()
        );
        // TODO: This is invalid
        assert_eq!(
            r#"{"foo":"bar","D","e":1}"#,
            serialize(&Test::D { e: 1 }).unwrap()
        );
    }

}
