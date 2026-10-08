use super::super::PasswordWorkGovernor;
use crate::error::ApiResult;

impl PasswordWorkGovernor {
    pub(crate) async fn verify_public_with_budget<A, R>(
        &self,
        encoded: &str,
        password: &str,
        verify_supplied: bool,
        admit: impl FnOnce() -> ApiResult<A> + Send + 'static,
        complete: impl FnOnce(bool, A) -> ApiResult<R> + Send + 'static,
    ) -> ApiResult<(bool, R)>
    where
        A: Send + 'static,
        R: Send + 'static,
    {
        let permit = self.try_acquire_public()?;
        let encoded = encoded.to_owned();
        let password = password.to_owned();
        Self::spawn_blocking(permit, move || {
            let admission = admit()?;
            let verified = verify_supplied && crate::auth::verify_password(&encoded, &password);
            let result = complete(verified, admission)?;
            Ok((verified, result))
        })
        .await?
    }
}
