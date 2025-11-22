use crate::ProviderAddress;

use paxwords_core::utils::ValueNotify;
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::mpsc;

mod network;

/// Providers manager. It bootstraps from IPFS nodes and searches for nodes that are providing
/// given `provider_key`. At the same time, it starts providing the same `provider_key`, thus allowing
/// other providers to find this node.
///
/// The finder does nothing to connect peers in the sync swarm - we just propagate our sync swarm
/// listen addresses to other providers (using gossipsub), hoping they'll be able to connect us.
/// So the main goal of this manager is to find and establish direct connections to other providers
/// so that they'll get our updates sooner. Sync addresses reported by other peers are sent to sync
/// manager over the `their_sync_addresses` channel.
pub struct Finder {
	/// Interface to listen on.
	interface: Ipv4Addr,
	/// Record key that all providers should provider.
	provider_key: String,
	/// Listen address of this peer sync swarm. It is reported to providers that we found.
	my_sync_address: Arc<ValueNotify<Option<ProviderAddress>>>,
	/// Other providers sync addresses sender.
	their_sync_addresses: mpsc::Sender<ProviderAddress>,
}

impl Finder {
	/// Crate new providers manager.
	pub fn new(
		interface: Ipv4Addr,
		provider_key: String,
		my_sync_address: Arc<ValueNotify<Option<ProviderAddress>>>,
		their_sync_addresses: mpsc::Sender<ProviderAddress>,
	) -> Self {
		Self {
			interface,
			provider_key,
			my_sync_address,
			their_sync_addresses,
		}
	}

	/// Run providers manager until completion.
	pub async fn run(&mut self) -> anyhow::Result<()> {
		network::Network::run(
			self.interface,
			&self.provider_key,
			&self.my_sync_address,
			&mut self.their_sync_addresses,
		)
		.await
	}
}
