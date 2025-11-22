use crate::{Error, ErrorKind};

use std::{
	fs::{File, OpenOptions, create_dir_all},
	io::{self, BufReader, BufWriter, Error as IoError, Seek, SeekFrom},
	path::{Path, PathBuf},
};
use thiserror_context::Context;

/// File-based entries storage.
pub(super) struct FileStorage {
	path: PathBuf,
	file: File,
}

impl FileStorage {
	/// Create storage backed by given path.
	pub fn at(path: &Path) -> Result<Self, Error> {
		create_dir_all(parent_path(path)?)
			.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
			.context("creating parent folder")?;

		let file = Self::open_file(path)?;
		Ok(FileStorage {
			path: path.into(),
			file,
		})
	}

	/// Return true if storage is empty.
	pub fn is_empty(&self) -> Result<bool, Error> {
		self.file
			.metadata()
			.map(|meta| meta.len() == 0)
			.map_err(|e| Error::from(ErrorKind::StorageReadFailed(e)))
			.context("getting file metadata")
	}

	/// Read from the storage. Storage is rewinded to the begin when this function is called.
	pub fn read<T>(
		&self,
		f: impl FnOnce(BufReader<&File>) -> Result<T, Error>,
	) -> Result<T, Error> {
		let mut reader = BufReader::new(&self.file);
		reader
			.seek(SeekFrom::Start(0))
			.map_err(|e| Error::from(ErrorKind::StorageReadFailed(e)))
			.context("seeking reader")?;
		f(reader)
	}

	/// Write to the storage. Bak file is created when this function is called. After that, the
	/// original file is truncated to zero length.
	pub fn write<T>(
		&mut self,
		f: impl FnOnce(BufWriter<&File>) -> Result<T, Error>,
	) -> Result<T, Error> {
		// we know that the file exists => we can create backup file name by just appending .bak to it
		let backup_path = backup_path(&self.path)?;

		// open backup file
		let mut backup_file = Self::open_file(&backup_path)?;

		// copy current -> backup
		copy_file_contents(&mut self.file, &mut backup_file).context("backing up")?;

		// ideally we shall write to separate file and then use atomic rename, but then we won't
		// be able to use file locks

		// truncate original file
		self.file
			.set_len(0)
			.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
			.context("error truncating file")?;
		self.file
			.seek(SeekFrom::Start(0))
			.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
			.context("error seeking in file")?;

		// now perform actual write
		let result = f(BufWriter::new(&self.file));

		// if write has failed, let's try to restore original file content
		if result.is_err()
			&& let Err(e) = copy_file_contents(&mut backup_file, &mut self.file)
		{
			tracing::error!("failed to restore file contents: {e:?}");
		}

		result
	}

	/// Open file and gain an exclusive lock on it.
	fn open_file(path: &Path) -> Result<File, Error> {
		// create if not exists + read + write
		let file = OpenOptions::new()
			.create(true)
			.truncate(false)
			.read(true)
			.write(true)
			.open(path)
			.map_err(|e| Error::from(ErrorKind::StorageOpenFailed(e)))
			.context("error opening file")?;

		// acquire an exclusive lock
		file.try_lock()
			.map_err(|e| Error::from(ErrorKind::StorageLockFailed(IoError::other(e))))
			.context("error acquiring file lock")?;

		Ok(file)
	}
}

/// Copy file contents from one to another.
fn copy_file_contents(source: &mut File, target: &mut File) -> Result<(), Error> {
	// truncate target file
	target
		.set_len(0)
		.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
		.context("error truncating target file")?;
	target
		.seek(SeekFrom::Start(0))
		.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
		.context("error seeking in target file")?;

	// seek to start of source file
	source
		.seek(SeekFrom::Start(0))
		.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
		.context("error seeking in source file")?;

	// copy file contents from source to target file
	io::copy(&mut BufReader::new(source), &mut BufWriter::new(target))
		.map_err(|e| Error::from(ErrorKind::StorageWriteFailed(e)))
		.context("error copying to target file")?;

	Ok(())
}

/// Get parent folder path.
fn parent_path(original_path: &Path) -> Result<&Path, Error> {
	original_path
		.parent()
		.ok_or_else(|| {
			Error::from(ErrorKind::StorageWriteFailed(IoError::other(
				"no parent folder",
			)))
		})
		.context("getting parent folder")
}

/// Append '.bak' to original file name.
fn backup_path(original_path: &Path) -> Result<PathBuf, Error> {
	let mut backup_path: PathBuf = original_path.into();
	let mut backup_file_name = match backup_path.file_name() {
		Some(file_name) => file_name.to_os_string(),
		_ => {
			return Err(Error::from(ErrorKind::StorageWriteFailed(IoError::other(
				"no file name component",
			))))
			.context("creating backup file");
		}
	};
	backup_file_name.push(".bak");
	backup_path.set_file_name(backup_file_name);

	Ok(backup_path)
}

#[cfg(test)]
mod tests {
	use std::io::Write;

	use super::*;
	use tempdir::TempDir;

	fn with_tempdir(f: impl FnOnce(&Path)) {
		let tempdir = TempDir::new("paxwords-tests").unwrap();
		let mut path: PathBuf = tempdir.path().into();
		path.push("paxwords");
		f(&path);
	}

	fn reader_content(mut reader: impl std::io::Read) -> String {
		let mut content = String::new();
		reader.read_to_string(&mut content).unwrap();
		content
	}

	#[test]
	fn creation_fails_when_path_is_invalid() {
		assert!(FileStorage::at(Path::new("a\0b")).is_err());
	}

	#[test]
	fn is_empty_works() {
		with_tempdir(|path| {
			let storage = FileStorage::at(path).unwrap();
			assert!(storage.is_empty().unwrap());
		});
	}

	#[test]
	fn full_storage_cycle() {
		with_tempdir(|path| {
			let mut storage = FileStorage::at(path).unwrap();
			storage
				.write(|mut f| {
					f.write_all("test".as_bytes()).unwrap();
					Ok(())
				})
				.unwrap();

			let content = storage.read(|f| Ok(reader_content(f))).unwrap();
			assert_eq!("test", content);
		});
	}

	#[test]
	fn file_is_locked_by_the_storage() {
		with_tempdir(|path| {
			let _storage = FileStorage::at(path).unwrap();
			assert!(FileStorage::at(path).is_err());
		});
	}

	#[test]
	fn backup_file_created() {
		with_tempdir(|path| {
			let mut storage = FileStorage::at(path).unwrap();

			let backup_path = backup_path(&storage.path).unwrap();
			assert!(!backup_path.exists());

			storage
				.write(|mut f| {
					f.write_all("test1".as_bytes()).unwrap();
					Ok(())
				})
				.unwrap();

			assert!(backup_path.exists());
			let content = std::fs::read_to_string(&backup_path).unwrap();
			assert_eq!("", content);

			storage
				.write(|mut f| {
					f.write_all("test2".as_bytes()).unwrap();
					Ok(())
				})
				.unwrap();

			assert!(backup_path.exists());
			let content = std::fs::read_to_string(backup_path).unwrap();
			assert_eq!("test1", content);
		});
	}

	#[test]
	fn original_file_contents_is_restored_on_write_error() {
		with_tempdir(|path| {
			{
				let mut storage = FileStorage::at(path).unwrap();
				storage
					.write(|mut f| {
						f.write_all("test1".as_bytes()).unwrap();
						Ok(())
					})
					.unwrap();
			}

			let content = std::fs::read_to_string(path).unwrap();
			assert_eq!("test1", content);

			{
				let mut storage = FileStorage::at(path).unwrap();
				storage
					.write(|mut f| {
						f.write_all("test2".as_bytes()).unwrap();
						Err::<(), _>(Error::from(ErrorKind::StateUnavailable))
					})
					.unwrap_err();
			}

			let content = std::fs::read_to_string(path).unwrap();
			assert_eq!("test1", content);
		});
	}
}
