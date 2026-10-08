//! Count manifest rows without materializing file objects before cycle admission.

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::Result;

pub(super) fn count_manifest_files(bytes: &[u8]) -> Result<usize> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let count = ManifestCounter.deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(count)
}

struct ManifestCounter;

impl<'de> DeserializeSeed<'de> for ManifestCounter {
    type Value = usize;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<usize, D::Error> {
        decoder.deserialize_map(ManifestVisitor)
    }
}

struct ManifestVisitor;

impl<'de> Visitor<'de> for ManifestVisitor {
    type Value = usize;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Drive manifest object")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<usize, M::Error> {
        let mut count = 0usize;
        while let Some(key) = map.next_key::<String>()? {
            if key == "files" {
                let rows = map.next_value_seed(FileCounter)?;
                count = count
                    .checked_add(rows)
                    .ok_or_else(|| serde::de::Error::custom("manifest row count overflowed"))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(count)
    }
}

struct FileCounter;

impl<'de> DeserializeSeed<'de> for FileCounter {
    type Value = usize;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<usize, D::Error> {
        decoder.deserialize_seq(FileVisitor)
    }
}

struct FileVisitor;

impl<'de> Visitor<'de> for FileVisitor {
    type Value = usize;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Drive manifest files array")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> std::result::Result<usize, S::Error> {
        let mut count = 0usize;
        while seq.next_element::<IgnoredAny>()?.is_some() {
            count = count
                .checked_add(1)
                .ok_or_else(|| serde::de::Error::custom("manifest row count overflowed"))?;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_array_is_counted_before_full_manifest_decode() {
        assert_eq!(
            count_manifest_files(br#"{"root":{},"files":[{},{}],"ignored":[1,2,3]}"#).unwrap(),
            2
        );
        assert!(count_manifest_files(br#"{"files":{}}"#).is_err());
        assert!(count_manifest_files(br#"{"files":[],"files":[{}]}"#).is_ok());
    }
}
