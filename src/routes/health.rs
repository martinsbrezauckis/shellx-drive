use axum::Json;

use crate::model::HealthResponse;

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "shellx-drive".to_string(),
    })
}
