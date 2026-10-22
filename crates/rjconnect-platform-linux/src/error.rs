use std::io;

use rjconnect_platform_api::PlatformError;

pub fn map_io_error(operation: &'static str, interface: &str, error: &io::Error) -> PlatformError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => PlatformError::PermissionDenied { operation },
        io::ErrorKind::NotFound | io::ErrorKind::NetworkDown => {
            PlatformError::InterfaceUnavailable {
                interface: interface.to_owned(),
            }
        }
        _ => PlatformError::OperationFailed {
            operation,
            message: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use rjconnect_platform_api::PlatformError;

    use super::*;

    #[test]
    fn maps_permission_failures_without_exposing_native_details() {
        let error = io::Error::from(io::ErrorKind::PermissionDenied);

        assert_eq!(
            map_io_error("activate AF_PACKET socket", "enp3s0", &error),
            PlatformError::PermissionDenied {
                operation: "activate AF_PACKET socket",
            }
        );
    }

    #[test]
    fn maps_missing_or_down_interfaces_to_the_stable_lifecycle_error() {
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::NetworkDown] {
            let error = io::Error::from(kind);

            assert_eq!(
                map_io_error("bind AF_PACKET socket", "enp3s0", &error),
                PlatformError::InterfaceUnavailable {
                    interface: "enp3s0".to_owned(),
                }
            );
        }
    }
}
