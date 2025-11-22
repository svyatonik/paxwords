use clap::Parser;
use parking_lot::{Mutex, RwLock};
use paxwords_core::{
	Encrypted, Entries, EntriesBatchOp, Entry, Error, InMemoryEntry, MasterPassword,
	apply_remote_entries, utils::event_loop,
};
use paxwords_demo_framework::{MergeAlgorithm, Randomness, select_command};
use paxwords_sync::EntriesSync;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::Stream;

/// Paxwordmgr demo app.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
	/// Network interface to listen on.
	#[arg(long, default_value = "0.0.0.0")]
	interface: std::net::Ipv4Addr,
	/// Path to storage file.
	#[arg(long)]
	storage: PathBuf,
}

/// A weak ref to UI entries.
type WeakEntries = Arc<RwLock<Weak<Vec<Arc<InMemoryEntry<String>>>>>>;

/// Simple console UI that emulates user actions.
struct Ui {
	master: Arc<MasterPassword>,
	entries: WeakEntries,
	batch_commands_sender: mpsc::Sender<Vec<EntriesBatchOp<String>>>,
	batch_commands_receiver: Mutex<Option<mpsc::Receiver<Vec<EntriesBatchOp<String>>>>>,
}

impl Ui {
	fn new(master: Arc<MasterPassword>, entries: Weak<Vec<Arc<InMemoryEntry<String>>>>) -> Self {
		let (batch_commands_sender, batch_commands_receiver) = mpsc::channel(32);
		Ui {
			master,
			entries: Arc::new(RwLock::new(entries)),
			batch_commands_sender,
			batch_commands_receiver: Mutex::new(Some(batch_commands_receiver)),
		}
	}
}

impl event_loop::Ui<String, u64> for Ui {
	fn entries_updated(&self, entries: Weak<Vec<Arc<InMemoryEntry<String>>>>) {
		*self.entries.write() = entries;
	}

	fn entries_received(&self, remote_entries: Vec<Entry<Encrypted, Encrypted>>) {
		tracing::info!("got new {} entries over network", remote_entries.len());

		let Some(my_entries) = self.entries.read().upgrade() else {
			// in real world we need to schedule processing here instead of dumb return
			tracing::info!(
				"entries update in progress. Ignoring {} entries",
				remote_entries.len()
			);
			return;
		};

		let batch = match apply_remote_entries::<MergeAlgorithm, _, _>(
			&self.master,
			&my_entries,
			remote_entries,
		) {
			Ok(batch) => batch,
			Err(e) => {
				tracing::info!("failed to apply remote entries: {e:?}");
				return;
			}
		};

		tracing::info!("queueing batch of {} commands", batch.len());
		if let Err(e) = self.batch_commands_sender.try_send(batch) {
			tracing::debug!("failed to queue batch of commands: {e:?}");
		}
	}

	fn commands(&self) -> impl Stream<Item = event_loop::UiCommand<String, u64>> + Unpin + 'static {
		let batch_commands_receiver = self
			.batch_commands_receiver
			.lock()
			.take()
			.expect("Ui::commands is called twice");

		type EntriesReceiver =
			oneshot::Receiver<Result<Weak<Vec<Arc<InMemoryEntry<String>>>>, paxwords_core::Error>>;

		let rng = Randomness::unlimited();
		let entries = self.entries.clone();
		let entries_receiver: Option<EntriesReceiver> = None;
		Box::pin(futures::stream::unfold(
			(rng, entries, entries_receiver, batch_commands_receiver),
			|(mut rng, entries, mut entries_receiver, mut batch_commands_receiver)| async move {
				// wait for result of previous command
				if let Some(entries_receiver) = entries_receiver.take() {
					let result = entries_receiver.await;
					tracing::debug!(
						"Ui command has finished with result: {:?}",
						result.as_ref().map(drop)
					);
					if let Ok(Ok(entries_updated)) = result {
						*entries.write() = entries_updated;
					}
				}

				// sleep for some time
				let sleep_duration = Duration::from_secs((rng.next_u16() % 60) as u64);
				tracing::debug!("Sleeping for {sleep_duration:?}");

				tokio::select! {
					batch = batch_commands_receiver.recv() => match batch {
						Some(batch) => {
							let (entries_sender, entries_receiver) = tokio::sync::oneshot::channel();
							let batch_op = event_loop::UiCommand::BatchOp {
								ops: batch,
								result_sender: entries_sender,
							};

							return Some((
								batch_op,
								(rng, entries, Some(entries_receiver), batch_commands_receiver),
							));
						},
						None => {
							tracing::debug!("batch channel has been closed");
							return None;
						},
					},
					_ = tokio::time::sleep(sleep_duration) => {}
				}

				// select UI command
				let entries_ref = entries.read().upgrade().unwrap();
				let (entries_sender, entries_receiver) = tokio::sync::oneshot::channel();
				let command = select_command(&mut rng, &entries_ref, entries_sender).unwrap();
				Some((
					command,
					(
						rng,
						entries,
						Some(entries_receiver),
						batch_commands_receiver,
					),
				))
			},
		))
	}

	/// Run until completion.
	async fn run(&self) {
		std::future::pending::<()>().await;
	}
}

#[tokio::main]
async fn main() -> Result<(), Error> {
	let _ = tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.with_writer(std::io::stderr)
		.try_init();

	let args = Args::parse();

	// storage
	let master = Arc::new(MasterPassword::from_password_secret("admin-password".into()).unwrap());
	let entries = Entries::<MergeAlgorithm>::new(&args.storage, master.clone()).unwrap();
	println!(
		"starting paxwords with master public: {:?}",
		master.public()
	);

	// emulate ui
	let ui = Ui::new(master.clone(), entries.unflushed_entries());

	// sync over network
	let sync = EntriesSync::new(master, args.interface);

	let el = event_loop::EventLoop::new(entries);
	el.run(ui, sync).await
}
