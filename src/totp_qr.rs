use qrcodegen::{QrCode, QrCodeEcc};

use crate::{
    auth::totp_uri,
    error::{ApiError, ApiResult},
};

const MIN_QR_SIZE: usize = 21;
const MAX_QR_SIZE: usize = 177;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TotpQr {
    pub(crate) size: u8,
    pub(crate) modules: String,
}

/// Encodes the server-issued TOTP URI into compact row-major module data.
///
/// `0` represents a light module and `1` a dark module. The browser only
/// paints this already validated matrix; it does not encode security material.
pub(crate) fn preflight(secret: &str, email: &str) -> ApiResult<(String, TotpQr)> {
    let uri = totp_uri(secret, email);
    let qr = encode(&uri)?;
    Ok((uri, qr))
}

pub(crate) fn encode(uri: &str) -> ApiResult<TotpQr> {
    let qr = QrCode::encode_text(uri, QrCodeEcc::Medium).map_err(|_| {
        ApiError::Validation("TOTP setup QR cannot encode the generated account data".to_string())
    })?;
    let size = usize::try_from(qr.size()).map_err(|_| invalid_qr_data())?;
    let mut modules = String::with_capacity(size.saturating_mul(size));
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            modules.push(if qr.get_module(x, y) { '1' } else { '0' });
        }
    }
    validate_matrix(size, &modules)?;
    Ok(TotpQr {
        size: size.try_into().map_err(|_| invalid_qr_data())?,
        modules,
    })
}

fn validate_matrix(size: usize, modules: &str) -> ApiResult<()> {
    if !(MIN_QR_SIZE..=MAX_QR_SIZE).contains(&size)
        || !(size - 17).is_multiple_of(4)
        || modules.len() != size.saturating_mul(size)
        || !modules.bytes().all(|module| matches!(module, b'0' | b'1'))
    {
        return Err(invalid_qr_data());
    }
    Ok(())
}

fn invalid_qr_data() -> ApiError {
    ApiError::Validation("TOTP setup QR encoder returned invalid module data".to_string())
}

#[cfg(test)]
mod tests {
    use super::{encode, preflight, validate_matrix};
    use qrcodegen::{QrCode, QrCodeEcc};

    #[test]
    fn encodes_validated_row_major_modules() {
        let uri = "otpauth://totp/ShellX%20Drive:alice%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=ShellX%20Drive";
        let encoded = encode(uri).unwrap();
        let expected = QrCode::encode_text(uri, QrCodeEcc::Medium).unwrap();
        let size = expected.size() as usize;

        assert_eq!(encoded.size as usize, size);
        assert_eq!(encoded.modules.len(), size * size);
        for y in 0..expected.size() {
            for x in 0..expected.size() {
                let index = y as usize * size + x as usize;
                assert_eq!(
                    encoded.modules.as_bytes()[index],
                    if expected.get_module(x, y) {
                        b'1'
                    } else {
                        b'0'
                    }
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_matrix_dimensions_and_content() {
        assert!(validate_matrix(20, &"0".repeat(400)).is_err());
        assert!(validate_matrix(21, &"0".repeat(440)).is_err());
        assert!(validate_matrix(21, &format!("{}x", "0".repeat(440))).is_err());
    }

    #[test]
    fn refuses_an_unencodable_disclosure_before_any_security_mutation() {
        assert!(preflight(&"A".repeat(4_000), "alice@example.test").is_err());
    }
}
