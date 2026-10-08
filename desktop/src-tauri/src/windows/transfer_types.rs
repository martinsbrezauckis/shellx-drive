//! Shared transfer execution outcomes.

use super::*;

pub(super) enum NonDeleteExecution {
    Complete,
    NeedsReview(Vec<ReviewItem>),
}

pub(super) enum BaselineFinalization {
    Complete(BTreeMap<String, BaselineEntry>),
    NeedsReview(ReviewItem),
}

pub(super) enum DownloadPublication {
    Published,
    NeedsReview { review: ReviewItem },
}
