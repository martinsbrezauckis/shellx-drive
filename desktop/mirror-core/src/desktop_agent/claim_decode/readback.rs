//! Strict readback claim payload decoding.

use serde::{Deserialize, Deserializer};

use super::super::{
    DesktopAgentDesktopViewPageRequest, DesktopAgentDesktopViewSection,
    DesktopAgentRootsPageRequest,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopViewPayload {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    section: Option<DesktopAgentDesktopViewSection>,
    after: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    limit: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoverRootsPayload {
    after: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    limit: Option<u8>,
}

pub(super) fn decode_desktop_view(
    value: serde_json::Value,
) -> std::result::Result<DesktopAgentDesktopViewPageRequest, ()> {
    super::decode::<DesktopViewPayload>(value).and_then(|value| {
        DesktopAgentDesktopViewPageRequest::new(value.section, value.after, value.limit)
            .map_err(|_| ())
    })
}

pub(super) fn decode_discover_roots(
    value: serde_json::Value,
) -> std::result::Result<DesktopAgentRootsPageRequest, ()> {
    super::decode::<DiscoverRootsPayload>(value).and_then(|value| {
        DesktopAgentRootsPageRequest::new(value.after, value.limit).map_err(|_| ())
    })
}

fn deserialize_optional_non_null<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Err(serde::de::Error::custom(
            "desktop-agent optional pagination fields cannot be null",
        ));
    }
    T::deserialize(value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
