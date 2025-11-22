use paxwords_core::{
	Encrypted, Entries, Entry, Error, InMemoryEntry, LastChanceDecision, Unencrypted,
	utils::event_loop::{UiCommand, UiResultSender, process_ui_command},
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Maximal number of users in the storage.
pub const MAX_USERS: u16 = u16::MAX;

/// Entries are uniquely identified by their user.
pub const HEADER_USER: &str = "user";
/// Entr holds just a single field in its body - associated password.
pub const BODY_PASSWORD: &str = "password";

/// Randomness source.
pub struct Randomness {
	rng: StdRng,
	remaining: Option<usize>,
}

impl Randomness {
	/// Create new randomness with given seed and limited number of steps.
	pub fn limited(seed: u64, limit: usize) -> Self {
		Self {
			rng: StdRng::seed_from_u64(seed),
			remaining: Some(limit),
		}
	}

	/// Create new unlimited randomness.
	pub fn unlimited() -> Self {
		Self {
			rng: StdRng::seed_from_u64(rand::rng().next_u64()),
			remaining: None,
		}
	}

	/// Return true if limit is reached.
	pub fn is_done(&self) -> bool {
		self.remaining == Some(0)
	}

	/// Return next `u16`. Panics if we've reached the end.
	pub fn next_u16(&mut self) -> u16 {
		match self.remaining {
			Some(0) => panic!("calling Randomness::next_u16 on finished Randomness"),
			Some(x) => {
				self.remaining = Some(x - 1);
				(self.rng.next_u32() % u16::MAX as u32) as _
			}
			None => (self.rng.next_u32() % u16::MAX as u32) as _,
		}
	}

	/// Return next `u16` or `None` if we've reached the end.
	pub fn maybe_next_u16(&mut self) -> Option<u16> {
		match self.remaining {
			Some(0) => None,
			Some(x) => {
				self.remaining = Some(x - 1);
				Some((self.rng.next_u32() % u16::MAX as u32) as _)
			}
			None => Some((self.rng.next_u32() % u16::MAX as u32) as _),
		}
	}
}

/// A helper for accessing header fields.
trait UiEntryHeader {
	/// Get user name.
	fn user(&self) -> String;
}

impl<Body> UiEntryHeader for Entry<Unencrypted<String>, Body> {
	fn user(&self) -> String {
		self.header.get(HEADER_USER).cloned().unwrap_or_default()
	}
}

/// A helper for accessing body fields.
trait UiEntryBody {
	/// Get password.
	fn password(&self) -> u64;
	/// Set password.
	fn set_password(&mut self, version: u64);
}

impl<Header> UiEntryBody for Entry<Header, Unencrypted<u64>> {
	fn password(&self) -> u64 {
		self.body.get(BODY_PASSWORD).cloned().unwrap_or_default()
	}

	fn set_password(&mut self, version: u64) {
		self.body.insert(BODY_PASSWORD.into(), version);
	}
}

/// A simple merge algorithm:
///
/// 1) entries are uniquely identified by user name in their header;
///
/// 2) of two 'passwords' we select larger one;
///
/// 3) instead of dropping entry #65536, we merge it into entry #0.
pub struct MergeAlgorithm;

impl paxwords_core::EntriesOrder for MergeAlgorithm {
	type HeaderV = String;

	fn cmp(
		left: &Entry<Unencrypted<String>, Encrypted>,
		right: &Entry<Unencrypted<String>, Encrypted>,
	) -> std::cmp::Ordering {
		left.user().cmp(&right.user())
	}
}

impl paxwords_core::MergeAlgorithm<String, u64> for MergeAlgorithm {
	fn merge(
		into: InMemoryEntry<String>,
		what: &InMemoryEntry<String>,
	) -> Result<Entry<Unencrypted<String>, Unencrypted<u64>>, Error> {
		let mut into_plain = into.decrypt::<u64>()?;
		let what_plain = what.decrypt::<u64>()?;
		into_plain.set_password(std::cmp::max(into_plain.password(), what_plain.password()));
		tracing::debug!(
			"merging remote entry {} and local entry {}: user={}, password={}",
			into.hash(),
			what.hash(),
			into_plain.user(),
			into_plain.password()
		);

		Ok(into_plain)
	}

	fn last_chance(_remote_entry: &InMemoryEntry<String>) -> LastChanceDecision {
		LastChanceDecision::MergeInto {
			merge_with: 0u16.into(),
		}
	}
}

/// Generate new for user with given index.
pub fn generate_new_entry(
	user_index: u16,
	password: u16,
) -> Entry<Unencrypted<String>, Unencrypted<u64>> {
	let username = format!("user-{}@gmail.com", user_index);
	let mut header = Unencrypted::new();
	header.insert(HEADER_USER.into(), username);

	let mut body = Unencrypted::new();
	body.insert(BODY_PASSWORD.into(), password as _);

	Entry { header, body }
}

/// Select new random UI command to perform on `entries`.
pub fn select_command(
	rng: &mut Randomness,
	entries: &[Arc<InMemoryEntry<String>>],
	result_sender: UiResultSender<String>,
) -> Option<UiCommand<String, u64>> {
	// maybe flush?
	let maybe_flush = rng.maybe_next_u16()?;
	if maybe_flush < u16::MAX / 8 {
		return Some(UiCommand::Flush { result_sender });
	}

	// select user index
	let user_index = rng.maybe_next_u16()?;
	// select user password
	let user_password = rng.maybe_next_u16()?;
	// prepare new entry
	let new_entry = generate_new_entry(user_index, user_password);

	// if there's no such entry in the storage => insert
	let Ok(entry_index) = entries.binary_search_by(|x| x.entry().user().cmp(&new_entry.user()))
	else {
		return Some(UiCommand::CreateEntry {
			entry: new_entry,
			result_sender,
		});
	};

	// else update existing entry
	Some(UiCommand::UpdateEntry {
		old_entry: entries[entry_index].clone(),
		entry: new_entry,
		result_sender,
	})
}

/// Perform random operation on `entries`. `data` is used as the source of randomness
/// for choosing the operation. The operation can be new entry addition, existing entry
/// update or flush.
pub fn perform_operation(rng: &mut Randomness, entries: &mut Entries<MergeAlgorithm>) {
	let (result_sender, _) = tokio::sync::oneshot::channel();
	let Some(command) = select_command(rng, entries.unflushed_entries_ref(), result_sender) else {
		return;
	};

	process_ui_command::<MergeAlgorithm, u64>(entries, command);
}
