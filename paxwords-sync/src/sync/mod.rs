use crate::{ProviderAddress, local_entries::LocalEntries};

pub use differences::{LocalPeer, PeerState};
pub use providers::Provider;

use bincode::Encode;
use futures::{
	future::FutureExt,
	stream::{FuturesUnordered, StreamExt},
	task::{Poll, Waker},
};
use paxwords_core::{
	MasterPassword, find_differences, retrieve_entries,
	utils::{ValueNotify, event_loop},
};
use std::{collections::HashSet, net::Ipv4Addr, sync::Arc};
use tokio::sync::mpsc;

mod differences;
mod network;
mod providers;

/// Synchronization manager. It ensures that providers found by [crate::Finder] are authentic
/// and provides encrypted transport between those.
pub struct Sync<HeaderV> {
	/// Interface to listen on.
	interface: Ipv4Addr,
	/// Master password is used here to generate pre-shared key to encrypt all traffic between
	/// authrntic providers.
	master: Arc<MasterPassword>,
	/// Local entries.
	local_entries: Arc<LocalEntries<HeaderV>>,
	/// Listen address of this peer sync swarm. It is reported to finder and propagated to other
	/// potential providers
	local_sync_address: Arc<ValueNotify<Option<ProviderAddress>>>,
	/// Other providers sync addresses receiver.
	remote_sync_addresses: mpsc::Receiver<ProviderAddress>,
	/// Channels where we send retrieved entries.
	entries_sender: mpsc::Sender<event_loop::SyncEvent>,
}

impl<HeaderV: Clone + Encode> Sync<HeaderV> {
	/// Crate new synchronization manager.
	pub fn new(
		interface: Ipv4Addr,
		master: Arc<MasterPassword>,
		local_entries: Arc<LocalEntries<HeaderV>>,
		local_sync_address: Arc<ValueNotify<Option<ProviderAddress>>>,
		remote_sync_addresses: mpsc::Receiver<ProviderAddress>,
		entries_sender: mpsc::Sender<event_loop::SyncEvent>,
	) -> Self {
		Self {
			interface,
			master,
			local_entries,
			local_sync_address,
			remote_sync_addresses,
			entries_sender,
		}
	}

	/// Run synchronization manager until completion.
	pub async fn run(&mut self) -> anyhow::Result<()> {
		let (mut providers_sender, mut providers_receiver) = tokio::sync::mpsc::channel(32);
		let network = network::Network::run(
			self.interface,
			&self.master,
			&self.local_entries,
			&self.local_sync_address,
			&mut self.remote_sync_addresses,
			&mut providers_sender,
		);
		tokio::pin!(network);

		// To avoid total havoc, we allow only one request to remote provider at a time.
		// This is handled by [providers::Providers] map. But here, to avoid failed requests, we need
		// to synchronize 'protocols' (a series of requests). So when we already have some 'protocol'
		// initiated with remote provider, we won't start another one.
		let mut active_protocols = HashSet::new();

		let mut active_differences = FuturesUnorderedPending::new();
		let mut active_retrievals = FuturesUnorderedPending::new();
		loop {
			tokio::select! {
				result = &mut network => {
					tracing::debug!("sync network has stopped with result: {result:?}");
					return result;
				},
				provider = providers_receiver.recv() => match provider {
					Some(provider) => {
						if !active_protocols.insert(*provider.peer_id()) {
							// we already started 'protocol' with that provider, just ignore
							// this report. This may be enhanced by queueing exchange instead
							// but it isn't critical
							tracing::debug!(
								"ignoring new provider {:?}: exchange already in progress",
								provider.peer_id(),
							);
							continue;
						}

						tracing::debug!(
							"new provider {:?} confirmed. Looking for different entries",
							provider.peer_id(),
						);

						let local_entries = self.local_entries.clone();
						active_differences.push(async move {
							let differences = find_differences(&*local_entries, &provider).await;
							match differences {
								Ok(differences) => Ok((provider, differences)),
								Err(e) => Err((provider, e)),
							}
						});
					},
					None => {
						tracing::debug!("providers channel has been closed");
						return Ok(());
					},
				},
				differences_result = active_differences.next() => match differences_result {
					Some(Ok((provider, differences))) => {
						let peer_id = *provider.peer_id();

						tracing::debug!(
							"found {} different entries with provider {:?}: {:?}",
							differences.len(),
							provider.peer_id(),
							differences,
						);

						if !differences.is_empty() {
							tracing::debug!("starting entries retrieval from {:?}", provider.peer_id());
							active_retrievals.push(
								retrieve_entries(provider, differences)
									.collect::<Vec<_>>()
									.map(move |entries| (peer_id, entries))
							);
						} else {
							active_protocols.remove(&peer_id);
						}
					},
					Some(Err((provider, e))) => {
						active_protocols.remove(provider.peer_id());
						tracing::debug!(
							"differences retrieval with {:?} has finished with error: {e:?}",
							provider.peer_id(),
						);
					},
					None => {
						tracing::debug!("differences channel has been closed");
						return Ok(());
					}
				},
				retrieval_result = active_retrievals.next() => match retrieval_result {
					Some((peer_id, entries)) => {
						let entries_len = entries.len();
						let entries = entries.into_iter().filter_map(Result::ok).map(|(_, entry)| entry).collect::<Vec<_>>();
						let errors = entries_len - entries.len();

						active_protocols.remove(&peer_id);

						tracing::debug!(
							"retrieved {} new entries from provider {peer_id:?}. Errors: {errors}",
							entries.len(),
						);

						if !entries.is_empty() {
							let entries_received = event_loop::SyncEvent::EntriesReceived { entries };
							if let Err(e) = self.entries_sender.try_send(entries_received) {
								tracing::debug!("failed to process new entries: {e:?}");
							}
						}
					},
					None => {
						tracing::info!("retrievals channel has been closed");
						return Ok(());
					}
				},
			}
		}
	}
}

/// `FuturesUnordered` that is pending when empty.
#[derive(Default)]
struct FuturesUnorderedPending<F> {
	futures: FuturesUnordered<F>,
	wake_me_on_new_future: Option<Waker>,
}

impl<F> FuturesUnorderedPending<F> {
	fn new() -> Self {
		Self {
			futures: FuturesUnordered::new(),
			wake_me_on_new_future: None,
		}
	}

	fn push(&mut self, future: F) {
		self.futures.push(future);
		if let Some(waker) = self.wake_me_on_new_future.take() {
			waker.wake();
		}
	}
}

impl<F: Future> futures::Stream for FuturesUnorderedPending<F> {
	type Item = F::Output;

	fn poll_next(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Self::Item>> {
		let Poll::Ready(Some(result)) = self.futures.poll_next_unpin(cx) else {
			self.wake_me_on_new_future = Some(cx.waker().clone());

			return Poll::Pending;
		};

		Poll::Ready(Some(result))
	}
}
