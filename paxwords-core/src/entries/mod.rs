pub use entries::{Entries, EntriesBatchOp};
pub use entry_encrypter::EntryEncrypter;
pub use in_memory_entry::{InMemoryEntries, InMemoryEntry};

#[allow(clippy::module_inception)]
mod entries;
mod entry_encrypter;
mod in_memory_entry;
mod storage;
