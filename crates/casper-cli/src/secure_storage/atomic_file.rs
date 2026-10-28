use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

/// Prepare a replacement beside its destination, with restrictive permissions
/// already applied before writing any data. Dropping it cancels the write.
pub(crate) struct PendingWrite {
    temporary: NamedTempFile,
    destination: PathBuf,
}

impl PendingWrite {
    pub(crate) fn new(destination: &Path, data: &[u8]) -> Result<Self, Box<dyn Error>> {
        let parent = destination.parent().ok_or("file has no parent directory")?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let mut temporary = NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temporary.write_all(data)?;
        temporary.as_file().sync_all()?;
        Ok(Self {
            temporary,
            destination: destination.to_path_buf(),
        })
    }

    pub(crate) fn persist(self) -> Result<(), Box<dyn Error>> {
        self.temporary
            .persist(self.destination)
            .map_err(|error| error.error)?;
        Ok(())
    }
}
