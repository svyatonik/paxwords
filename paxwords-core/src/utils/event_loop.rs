//! A simple event loop that ties UI, Sync and Storage together.

use crate::{
	EntriesOrder, Error,
	entries::{Entries, EntriesBatchOp, InMemoryEntries, InMemoryEntry},
	types::{Encrypted, Entry, Unencrypted},
};

use bincode::{Decode, Encode};
use std::sync::{Arc, Weak};
use tokio::sync::oneshot::Sender as OneshotSender;
use tokio_stream::{Stream, StreamExt};
use zeroize::Zeroize;

/// Ui command result sender;
pub type UiResultSender<HeaderV> =
	OneshotSender<Result<Weak<Vec<Arc<InMemoryEntry<HeaderV>>>>, Error>>;

/// Commands from the UI.
pub enum UiCommand<HeaderV, BodyV> {
	/// A new entry has been created in UI.
	CreateEntry {
		/// An unencrypted new entry.
		entry: Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>,
		/// Command result sender.
		result_sender: UiResultSender<HeaderV>,
	},
	/// An entry has been updated in UI.
	UpdateEntry {
		/// Old entry.
		old_entry: Arc<InMemoryEntry<HeaderV>>,
		/// An unencrypted updated entry.
		entry: Entry<Unencrypted<HeaderV>, Unencrypted<BodyV>>,
		/// Command result sender.
		result_sender: UiResultSender<HeaderV>,
	},
	/// Entries have been reordered by the UI. This also calls flush after all operations
	/// are applied.
	BatchOp {
		/// Operations to perform on the entries.
		ops: Vec<EntriesBatchOp<HeaderV>>,
		/// Command result sender.
		result_sender: UiResultSender<HeaderV>,
	},
	/// Flush entries.
	Flush {
		/// Command result sender.
		result_sender: UiResultSender<HeaderV>,
	},
}

impl<HeaderV, BodyV> std::fmt::Display for UiCommand<HeaderV, BodyV> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match *self {
			Self::CreateEntry { .. } => write!(f, "CreateEntry"),
			Self::UpdateEntry { ref old_entry, .. } => write!(f, "UpdateEntry({old_entry:?})"),
			Self::BatchOp { ref ops, .. } => write!(f, "BatchOp({})", ops.len()),
			Self::Flush { .. } => write!(f, "Flush"),
		}
	}
}

/// Events from the sync service.
pub enum SyncEvent {
	/// A new entries have been received from other trusted source.
	EntriesReceived {
		/// Entries and their indices.
		entries: Vec<Entry<Encrypted, Encrypted>>,
	},
}

/// An abstraction over UI.
pub trait Ui<HeaderV, BodyV> {
	/// Entries have been updated in the in-memory storage.
	fn entries_updated(&self, entries: Weak<Vec<Arc<InMemoryEntry<HeaderV>>>>);
	/// A new entries have been received by the sync.
	fn entries_received(&self, remote_entries: Vec<Entry<Encrypted, Encrypted>>);
	/// A stream of UI events.
	fn commands(&self) -> impl Stream<Item = UiCommand<HeaderV, BodyV>> + Unpin + 'static;

	/// Run until completion.
	fn run(&self) -> impl Future<Output = ()>;
}

/// An abstraction over Sync.
pub trait Sync<HeaderV> {
	/// Entries have been updated in the persistent storage.
	fn entries_updated(&self, entries: Weak<InMemoryEntries<HeaderV>>);
	/// A stream of Sync events.
	fn events(&mut self) -> impl Stream<Item = SyncEvent> + Unpin + 'static;

	/// Run until completion.
	fn run(&self) -> impl Future<Output = ()>;
}

/// A simple tokio-based event loop.
pub struct EventLoop<Order: EntriesOrder> {
	entries: Entries<Order>,
}

impl<Order: EntriesOrder> EventLoop<Order>
where
	Order::HeaderV: Clone + Decode<()> + Encode + Zeroize,
{
	/// Create new even loop over given entries.
	pub fn new(entries: Entries<Order>) -> Self {
		Self { entries }
	}

	/// Run event loop until.
	pub async fn run<BodyV: Encode + Zeroize>(
		mut self,
		ui: impl Ui<Order::HeaderV, BodyV>,
		mut sync: impl Sync<Order::HeaderV>,
	) -> Result<(), Error> {
		let mut ui_commands = ui.commands();
		let mut sync_events = sync.events();

		sync.entries_updated(self.entries.flushed_entries());

		let ui_run = ui.run();
		let sync_run = sync.run();
		futures::pin_mut!(ui_run, sync_run);

		loop {
			tokio::select! {
				_ = &mut ui_run => {
					tracing::debug!("stopping event loop: ui has exited");
					return Ok(());
				}
				_ = &mut sync_run => {
					tracing::debug!("stopping event loop: sync has exited");
					return Ok(());
				}

				ui_command = ui_commands.next() => match ui_command {
					Some(command) => {
						if process_ui_command::<Order, BodyV>(&mut self.entries, command) {
							sync.entries_updated(self.entries.flushed_entries());
						}

						let unflushed = self.entries.unflushed_entries_ref();
						let flushed = self.entries.flushed_entries_ref();
						tracing::info!(
							"unflushed: count={}. flushed: count={}, l0_root={}",
							unflushed.len(),
							flushed.entries.len(),
							flushed.state.l0_hash(),
						);
					},
					None => {
						tracing::debug!("stopping event loop: ui events channel has been closed");
						return Ok(());
					}
				},
				sync_event = sync_events.next() => match sync_event {
					Some(SyncEvent::EntriesReceived { entries }) => {
						ui.entries_received(entries);
					}
					None => {
						tracing::debug!("stopping event loop: sync events channel has been closed");
						return Ok(());
					}
				},
			}
		}
	}
}

/// Returns true if entries have been flushed.
pub fn process_ui_command<Order: EntriesOrder, BodyV: Encode + Zeroize>(
	entries: &mut Entries<Order>,
	ui_command: UiCommand<Order::HeaderV, BodyV>,
) -> bool
where
	Order::HeaderV: Clone + Decode<()> + Encode + Zeroize,
{
	match ui_command {
		UiCommand::CreateEntry {
			entry,
			result_sender,
		} => {
			let result = entries.insert(entry).map(|_| entries.unflushed_entries());

			match result.as_ref() {
				Ok(_) => tracing::debug!("a new entry has been created"),
				Err(e) => tracing::debug!("entry creation has failed: {e:?}"),
			}

			let _ = result_sender.send(result);
			false
		}
		UiCommand::UpdateEntry {
			old_entry,
			entry,
			result_sender,
		} => {
			let result = entries
				.update(old_entry, entry)
				.map(|_| entries.unflushed_entries());

			match result.as_ref() {
				Ok(_) => tracing::debug!("an entry has been updated:"),
				Err(e) => tracing::debug!("entry update has failed: {e:?}"),
			}

			let _ = result_sender.send(result);
			false
		}

		UiCommand::Flush { result_sender } => {
			let result = entries.flush().map(|_| entries.unflushed_entries());

			match result.as_ref() {
				Ok(_) => tracing::debug!("entries have been flushed"),
				Err(e) => tracing::debug!("entries flush has failed: {e:?}"),
			}

			let is_updated = result.is_ok();
			let _ = result_sender.send(result);

			is_updated
		}
		UiCommand::BatchOp { ops, result_sender } => {
			let n_ops = ops.len();
			let result = entries
				.apply_batch(ops)
				.and_then(|_| entries.flush())
				.map(|_| entries.unflushed_entries());

			match result.as_ref() {
				Ok(_) => tracing::debug!("a batch with {n_ops} operations has been applied"),
				Err(e) => tracing::debug!("a batch with {n_ops} has failed: {e:?}"),
			}

			let is_updated = result.is_ok();
			let _ = result_sender.send(result);

			is_updated
		}
	}
}
