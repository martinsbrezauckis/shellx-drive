//! Marker publication bound to the captured Windows pair-root identity.

use super::{
    pair_marker,
    pair_root_identity::{missing_root_identity, open_identity_chain, PairRootGuard},
    *,
};

impl PairRootGuard {
    pub(super) fn write_or_recognize_marker(
        &self,
        root: &Path,
        marker: &PairMarker,
    ) -> CoreResult<PairMarkerDisposition> {
        self.write_or_recognize_marker_with(root, marker, || Ok(()))
    }

    fn write_or_recognize_marker_with<F>(
        &self,
        root: &Path,
        marker: &PairMarker,
        before_publication: F,
    ) -> CoreResult<PairMarkerDisposition>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        let guarded = self
            ._chains
            .iter()
            .find(|chain| chain.path == root)
            .and_then(|chain| chain.identities.last())
            .is_some_and(|identity| identity == &self.required_identity);
        if !guarded {
            return Err(DesktopError::InvalidState(
                "pair marker root does not match its physical identity guard".to_string(),
            ));
        }
        let publication_chain = open_identity_chain(root)?;
        let current = publication_chain
            .identities
            .last()
            .ok_or_else(|| missing_root_identity("marker publication"))?;
        if current != &self.required_identity {
            return Err(DesktopError::UnsafePath(format!(
                "the new Drive folder changed before marker publication: {}",
                root.display()
            )));
        }
        before_publication()?;
        let disposition = pair_marker::write_or_recognize(root, marker)?;
        drop(publication_chain);
        Ok(disposition)
    }

    #[cfg(test)]
    pub(super) fn write_or_recognize_marker_with_test_hook<F>(
        &self,
        root: &Path,
        marker: &PairMarker,
        before_publication: F,
    ) -> CoreResult<PairMarkerDisposition>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        self.write_or_recognize_marker_with(root, marker, before_publication)
    }
}
