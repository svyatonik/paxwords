//! Syncing paxwords over network using various `libp2p` techniques.

#![deny(missing_docs)]

use bincode::{Decode, Encode};
use libp2p::{Multiaddr, PeerId};
use paxwords_core::{
	InMemoryEntries, MasterPassword,
	utils::{ValueNotify, event_loop},
};
use std::{
	net::Ipv4Addr,
	sync::{Arc, Weak},
};
use tokio::sync::mpsc;
use tokio_util::either::Either;

pub use sync::{LocalPeer, PeerState, Provider};

mod bincodec;
mod finder;
mod local_entries;
mod sync;

/// Provider address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAddress {
	/// Provider peer id.
	pub peer_id: PeerId,
	/// Provider listens on those addresses.
	pub addresses: Vec<Multiaddr>,
}

#[derive(Decode, Encode)]
struct EncodableProviderAddress {
	/// Provider peer id.
	pub peer_id: Vec<u8>,
	/// Provider listens on those addresses.
	pub addresses: Vec<Vec<u8>>,
}

impl From<ProviderAddress> for EncodableProviderAddress {
	fn from(value: ProviderAddress) -> Self {
		Self {
			peer_id: value.peer_id.to_bytes(),
			addresses: value.addresses.into_iter().map(|x| x.to_vec()).collect(),
		}
	}
}

impl TryFrom<EncodableProviderAddress> for ProviderAddress {
	type Error = ();

	fn try_from(value: EncodableProviderAddress) -> Result<Self, Self::Error> {
		Ok(ProviderAddress {
			peer_id: PeerId::from_bytes(&value.peer_id).map_err(drop)?,
			addresses: value
				.addresses
				.into_iter()
				.map(Multiaddr::try_from)
				.collect::<Result<Vec<_>, _>>()
				.map_err(drop)?,
		})
	}
}

/// Synchronization manager. It ensures that providers found by [crate::Finder] are authentic
/// and provides encrypted transport between those.
pub struct EntriesSync<HeaderV> {
	/// Master password is used here to generate pre-shared key to encrypt all traffic between
	/// authrntic providers.
	master: Arc<MasterPassword>,
	/// Weak reference to my persistent entries.
	self_peer: Arc<local_entries::LocalEntries<HeaderV>>,
	/// Listen address of this peer sync swarm. It is reported to finder and propagated to other
	/// potential providers.
	my_sync_address: Arc<ValueNotify<Option<ProviderAddress>>>,
	/// Remote entries are sent over this channel.
	sync_events_sender: mpsc::Sender<event_loop::SyncEvent>,
	/// Entries that are found on network are sent over this channel.
	sync_events_receiver: Option<mpsc::Receiver<event_loop::SyncEvent>>,
	/// Interface to listen on.
	interface: Ipv4Addr,
}

impl<HeaderV> EntriesSync<HeaderV> {
	/// Crate new entries synchronization service.
	pub fn new(master: Arc<MasterPassword>, interface: Ipv4Addr) -> Self {
		let (sync_events_sender, sync_events_receiver) = mpsc::channel(32);
		Self {
			master,
			self_peer: Arc::new(local_entries::LocalEntries::<HeaderV>::default()),
			my_sync_address: Arc::new(ValueNotify::new(None)),
			sync_events_sender,
			sync_events_receiver: Some(sync_events_receiver),
			interface,
		}
	}
}

impl<HeaderV: Clone + Encode> event_loop::Sync<HeaderV> for EntriesSync<HeaderV> {
	fn entries_updated(&self, entries: Weak<InMemoryEntries<HeaderV>>) {
		self.self_peer.update(entries);
	}

	fn events(
		&mut self,
	) -> impl tokio_stream::Stream<Item = event_loop::SyncEvent> + Unpin + 'static {
		// it should be called once
		let maybe_sync_events_channel = self.sync_events_receiver.take();
		match maybe_sync_events_channel {
			Some(sync_events_receiver) => Either::Left(
				tokio_stream::wrappers::ReceiverStream::new(sync_events_receiver),
			),
			None => Either::Right(futures::stream::empty()),
		}
	}

	async fn run(&self) {
		// we (and other owners of the master key) will provide following key in IPFS
		let public_as_hex = hex::encode(self.master.public().as_bytes());
		let provider_key = format!("/paxwords/sync/1.0.0/{public_as_hex}");

		// we'll have two swarms: one to find other master key owners (providers) on the network
		// and another to synchronize our entries with each other. Second (sync) swarm
		// communication is protected with the `master`. The first is just a regular IPFS-like
		// swarm, which will also be sending the listen address of sync swarm to providers
		// it'll found.

		// addresses of other providers are sent over this channel
		let (sync_addresses_sender, sync_addresses_receiver) = mpsc::channel(32);

		// first swarm that is finding other providers
		let mut finder = finder::Finder::new(
			self.interface,
			provider_key,
			self.my_sync_address.clone(),
			sync_addresses_sender,
		);
		// second swarm that is syncing entries
		let mut sync = sync::Sync::new(
			self.interface,
			self.master.clone(),
			self.self_peer.clone(),
			self.my_sync_address.clone(),
			sync_addresses_receiver,
			self.sync_events_sender.clone(),
		);

		// once any swarm exits, sync service is also exits
		tokio::select! {
			result = finder.run() => {
				tracing::debug!("finder swarm has exited with status: {result:?}");
			},
			result = sync.run() => {
				tracing::debug!("sync swarm has exited with status: {result:?}");
			},
		}
	}
}
