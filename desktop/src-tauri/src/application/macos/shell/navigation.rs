//! Native-to-frontend navigation requests for the macOS shell.

use tauri::{Emitter, Manager};

const OPEN_REVIEWS_EVENT: &str = "shellx-drive-open-reviews";

pub(super) fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub(super) fn show_reviews(app: &tauri::AppHandle) {
    show_main_window(app);
    let _ = app.emit(OPEN_REVIEWS_EVENT, ());
}

#[cfg(test)]
mod tests {
    use super::OPEN_REVIEWS_EVENT;

    #[test]
    fn review_tray_navigation_uses_the_shared_frontend_event() {
        assert_eq!(OPEN_REVIEWS_EVENT, "shellx-drive-open-reviews");
    }
}
