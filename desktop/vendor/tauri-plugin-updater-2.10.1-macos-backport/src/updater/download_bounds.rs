// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::error::{Error, Result};

pub(super) const MAX_UPDATE_FEED_BYTES: usize = 1024 * 1024;
pub(super) const MAX_COMPRESSED_INSTALLER_BYTES: usize = 512 * 1024 * 1024;

pub(super) struct BoundedBody {
    bytes: Vec<u8>,
    limit: usize,
    label: &'static str,
}

impl BoundedBody {
    pub(super) fn new(
        declared_size: Option<u64>,
        limit: usize,
        label: &'static str,
    ) -> Result<Self> {
        if declared_size.is_some_and(|declared| declared > limit as u64) {
            return Err(limit_error(label, limit));
        }
        Ok(Self {
            bytes: Vec::new(),
            limit,
            label,
        })
    }

    pub(super) fn push(&mut self, chunk: &[u8]) -> Result<()> {
        checked_body_len(self.bytes.len(), chunk.len(), self.limit, self.label)?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    pub(super) fn push_and_then(&mut self, chunk: &[u8], on_accepted: impl FnOnce()) -> Result<()> {
        self.push(chunk)?;
        on_accepted();
        Ok(())
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

fn checked_body_len(
    current: usize,
    chunk: usize,
    limit: usize,
    label: &'static str,
) -> Result<usize> {
    let next = current
        .checked_add(chunk)
        .ok_or_else(|| limit_error(label, limit))?;
    if next > limit {
        return Err(limit_error(label, limit));
    }
    Ok(next)
}

fn limit_error(label: &'static str, limit: usize) -> Error {
    Error::ResponseTooLarge { label, limit }
}

#[cfg(test)]
#[path = "download_bounds_tests.rs"]
mod tests;
