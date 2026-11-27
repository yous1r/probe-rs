//! Bounded reads for local credentials; errors never contain credential contents.
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub fn read_secret_file(path: &Path, maximum_bytes: u64) -> io::Result<String> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential file requires mode 0600 or stricter",
            ));
        }
    }
    let mut contents = String::new();
    file.take(maximum_bytes.saturating_add(1))
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential file exceeds size limit",
        ));
    }
    Ok(contents)
}

pub fn valid_token(token: &str) -> bool {
    (16..=256).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_bounded_and_header_safe() {
        assert!(valid_token("a-valid-test-token-123"));
        assert!(!valid_token("short"));
        assert!(!valid_token("a-valid-test-token\r\n"));
        assert!(!valid_token(&"x".repeat(257)));
    }

    #[cfg(unix)]
    #[test]
    fn credential_permissions_and_size_are_checked() {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = std::env::temp_dir().join(format!("rprobe-secret-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"test-secret-value").unwrap();
        assert_eq!(read_secret_file(&path, 100).unwrap(), "test-secret-value");
        assert!(read_secret_file(&path, 3).is_err());
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(
            read_secret_file(&path, 100).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(path).unwrap();
    }
}
