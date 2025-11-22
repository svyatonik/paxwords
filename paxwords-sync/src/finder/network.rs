use crate::{EncodableProviderAddress, ProviderAddress, bincodec::bincode_config};

use libp2p::{
	Swarm, autonat,
	futures::StreamExt,
	gossipsub, identify, kad, mdns, noise,
	swarm::{NetworkBehaviour, StreamProtocol, SwarmEvent},
	tcp, yamux,
};
use paxwords_core::utils::ValueNotify;
use std::{net::Ipv4Addr, time::Duration};
use tokio::sync::mpsc;
use tracing::instrument;

/// Kademlia protocol name used by IPFS.
const IPFS_KAD_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");
/// Identify protocol name used by IPFS.
const IPFS_IDENTIFY_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/id/1.0.0");

/// Time between two consequent providers search requests. There can be two
/// overlapping providers search requests (depending on request timeout).
const PROVIDER_SEARCH_INTERVAL: Duration = Duration::from_secs(60);
/// Time between two consequent sync address gossip messages are generated.
const REPUBLISH_SYNC_ADDRESS_INTERVAL: Duration = Duration::from_secs(60);

/// IPFS bootnodes IDs.
const BOOTNODES: [&str; 4] = [
	"QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
	"QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];
/// IPFS bootnode address.
const BOOTNODES_ADDRESS: &str = "/dnsaddr/bootstrap.libp2p.io";

/// Our network behaviour.
#[derive(NetworkBehaviour)]
pub struct Network {
	/// Autonat to discover whether we're behind NAT.
	autonat: autonat::Behaviour,
	/// Kademlia for finding remote peers.
	kademlia: kad::Behaviour<kad::store::MemoryStore>,
	/// MDNS for finding local peers.
	mdns: mdns::tokio::Behaviour,
	/// Identify to exchange addresses.
	identify: identify::Behaviour,
	/// Gossipsub to send our sync address updates to other providers.
	gossipsub: gossipsub::Behaviour,
}

impl Network {
	/// Run finder network and search for providers of `required_key`.
	#[instrument(skip_all, name = "Network::run")]
	pub async fn run(
		interface: Ipv4Addr,
		provider_key: &str,
		my_sync_address: &ValueNotify<Option<ProviderAddress>>,
		their_sync_addresses: &mut mpsc::Sender<ProviderAddress>,
	) -> anyhow::Result<()> {
		// generate keypair
		let local_key = libp2p::identity::Keypair::generate_ed25519();
		let local_public = local_key.public().clone();
		let local_peer_id = local_public.to_peer_id();
		// prepare network behaviour
		let network = Network {
			autonat: {
				let config = autonat::Config::default();
				autonat::Behaviour::new(local_peer_id, config)
			},
			kademlia: {
				let mut cfg = kad::Config::new(IPFS_KAD_PROTO_NAME);
				// single query (!request) timeout to 60 seconds
				cfg.set_query_timeout(Duration::from_secs(60));
				// our record expires in 12 minutes
				cfg.set_provider_record_ttl(Some(Duration::from_secs(10 * 60)));
				// reannounce every 3 minutes
				cfg.set_provider_publication_interval(Some(Duration::from_secs(60)));

				let store = kad::store::MemoryStore::new(local_peer_id);
				let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, cfg);

				// set Kademlia mode to server, otherwise (if set to Client or auto-detected as Client)
				// we won't be able to act as provider
				kademlia.set_mode(Some(kad::Mode::Server));

				// Add the bootnodes to the local routing table. `libp2p-dns` built
				// into the `transport` resolves the `dnsaddr` when Kademlia tries
				// to dial these nodes.
				for peer in &BOOTNODES {
					kademlia.add_address(
						&peer.parse().expect("peer IDs are static"),
						BOOTNODES_ADDRESS.parse().expect("address is static"),
					);
				}

				kademlia
			},
			mdns: {
				let config = mdns::Config::default();
				mdns::tokio::Behaviour::new(config, local_peer_id)?
			},
			identify: identify::Behaviour::new(identify::Config::new(
				IPFS_IDENTIFY_PROTO_NAME.to_string(),
				local_public,
			)),
			gossipsub: {
				let gossipsub_config = gossipsub::ConfigBuilder::default()
					.heartbeat_interval(Duration::from_secs(10))
					.validation_mode(gossipsub::ValidationMode::Strict)
					.build()?;

				// build a gossipsub network behaviour

				gossipsub::Behaviour::new(
					gossipsub::MessageAuthenticity::Signed(local_key.clone()),
					gossipsub_config,
				)
				.map_err(|e| anyhow::anyhow!("{e}"))?
			},
		};

		// libp2p swarm = network
		let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
			// use tokio runtime
			.with_tokio()
			// TCP-based default transport: noise for encryption + yamux for multiplexing
			.with_tcp(
				tcp::Config::default().nodelay(true),
				noise::Config::new,
				yamux::Config::default,
			)?
			// with DNS name resolving
			.with_dns()?
			// add Kademlia behavior (a set of protocols)
			.with_behaviour(|_| network)
			.expect("infallible")
			.build();

		tracing::info!("starting finder swarm {local_peer_id}");

		// gossip topic we're interested in
		let topic = format!("{provider_key}/sync_address");
		let topic = gossipsub::Sha256Topic::new(topic);
		swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

		// start listening on given IPV4 interface + random port
		swarm.listen_on(
			libp2p::Multiaddr::empty()
				.with(libp2p::multiaddr::Protocol::Ip4(interface))
				.with(libp2p::multiaddr::Protocol::Tcp(0)),
		)?;

		// start bootstraping kademlia from IPFS bootnodes
		swarm.behaviour_mut().kademlia.bootstrap()?;

		// start providing `requred_key` so that other peers can find us too
		swarm
			.behaviour_mut()
			.kademlia
			.start_providing(provider_key.as_bytes().to_vec().into())?;

		fn send_sync_addresses(
			swarm: &mut Swarm<Network>,
			topic: &gossipsub::Sha256Topic,
			my_sync_address: &ValueNotify<Option<ProviderAddress>>,
		) {
			let Some(sync_address) = my_sync_address.get() else {
				// can't send anything if we've stopped listening
				return;
			};

			tracing::debug!("going to gossip our sync address: {sync_address:?}");

			let sync_address: EncodableProviderAddress = sync_address.into();
			let sync_address = match bincode::encode_to_vec(sync_address, bincode_config()) {
				Ok(sync_address) => sync_address,
				Err(e) => {
					tracing::debug!("failed to encode our sync address: {e:?}");
					return;
				}
			};

			// it can fail immediately if there are no peers who're subscribed to this topic
			if let Err(e) = swarm
				.behaviour_mut()
				.gossipsub
				.publish(topic.clone(), sync_address)
			{
				tracing::debug!("failed to gossip our sync address: {e:?}");
			}
		}

		// leave some time for kademlia and mDNS to bootstrap
		let mut restart_providers_search =
			tokio_stream::wrappers::IntervalStream::new(tokio::time::interval_at(
				tokio::time::Instant::now() + Duration::from_secs(10),
				PROVIDER_SEARCH_INTERVAL,
			));
		// leave some time for providers search to complete
		let mut republish_sync_address =
			tokio_stream::wrappers::IntervalStream::new(tokio::time::interval_at(
				tokio::time::Instant::now() + Duration::from_secs(20),
				REPUBLISH_SYNC_ADDRESS_INTERVAL,
			));
		loop {
			let event = tokio::select! {
				event = swarm.select_next_some() => event,
				_ = my_sync_address.wait_change() => {
					send_sync_addresses(&mut swarm, &topic, my_sync_address);
					continue;
				},
				_ = restart_providers_search.next() => {
					swarm
						.behaviour_mut()
						.kademlia
						.get_providers(provider_key.as_bytes().to_vec().into());
					continue;
				}
				_ = republish_sync_address.next() => {
					send_sync_addresses(&mut swarm, &topic, my_sync_address);
					continue;
				}
			};

			match event {
				SwarmEvent::NewListenAddr { address, .. } => {
					tracing::info!("listening on {address:?}");
				}
				SwarmEvent::ListenerError { error, .. } => {
					tracing::warn!("listener error: {error:?}");
				}
				SwarmEvent::ExpiredListenAddr { address, .. } => {
					tracing::error!("listen address expired: {address:?}");
				}
				SwarmEvent::ListenerClosed {
					addresses, reason, ..
				} => {
					tracing::error!("listen {addresses:?} closed: {reason:?}");
				}

				SwarmEvent::ConnectionEstablished { peer_id, .. } => {
					tracing::trace!("peer {peer_id} connected");
				}
				SwarmEvent::ConnectionClosed { peer_id, .. } => {
					tracing::trace!("peer {peer_id} disconnected");
				}

				SwarmEvent::Behaviour(NetworkEvent::Kademlia(
					kad::Event::OutboundQueryProgressed {
						result:
							kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
								providers,
								..
							})),
						..
					},
				)) => {
					// all we want here is try to connect that peer. Otherwise our gossip messages won't probably
					// be delivered to that peer
					for provider in providers {
						if provider == local_peer_id {
							continue;
						}

						tracing::debug!("found provider {provider:?}");

						swarm.behaviour_mut().gossipsub.add_explicit_peer(&provider);

						if !swarm.is_connected(&provider) {
							tracing::debug!("trying to dial provider {provider:?}");

							if let Err(e) = swarm.dial(provider) {
								tracing::debug!("failed to dial provider {provider:?}: {e:?}");
							}
							continue;
						}
					}
				}
				SwarmEvent::Behaviour(NetworkEvent::Mdns(mdns::Event::Discovered(peers))) => {
					// always remember local peers addresses, so that we'll be able to found providers even
					// without external connections
					for (peer, address) in peers {
						if peer == local_peer_id {
							continue;
						}

						if !swarm.is_connected(&peer) {
							tracing::debug!("adding mDNS peer: {peer:?} with address {address:?}");

							swarm.add_peer_address(peer, address.clone());
							swarm.behaviour_mut().kademlia.add_address(&peer, address);
							if let Err(e) = swarm.dial(peer) {
								tracing::debug!("failed to dial mDNS peer {peer:?}: {e:?}");
							}
						}
					}
				}
				SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Message {
					message,
					..
				})) => {
					tracing::debug!(
						"received sync addresses gossip message from {:?}",
						message.source
					);

					// try to dial other message source (we could've received message from
					// some intermediate peer)
					if let Some(provider) = message.source
						&& provider != local_peer_id
						&& !swarm.is_connected(&provider)
					{
						tracing::debug!(
							"trying to dial gossip message source {:?}",
							message.source
						);

						if let Err(e) = swarm.dial(provider) {
							tracing::debug!(
								"failed to dial gossip message source {:?}: {e:?}",
								message.source
							);
						}
					}

					// we've got (hopefully address) of other peer sync provider
					let peer_sync_address =
						bincode::decode_from_slice::<EncodableProviderAddress, _>(
							&message.data,
							bincode_config(),
						)
						.map_err(|e| anyhow::anyhow!("{e:?}"))
						.and_then(|addr| {
							ProviderAddress::try_from(addr.0).map_err(|e| {
								anyhow::anyhow!("provider address can not be decoded: {e:?}")
							})
						});

					// if we've failed to decode address, just log it
					let peer_sync_address = match peer_sync_address {
						Ok(peer_sync_address) => peer_sync_address,
						Err(e) => {
							tracing::debug!(
								"got bad sync address from peer {:?}: {e:?}",
								message.source
							);
							continue;
						}
					};

					// send to sync swarm
					if let Err(e) = their_sync_addresses.try_send(peer_sync_address) {
						tracing::warn!("failed to send new provider address to sync swarm: {e:?}");
					}
				}
				_ => (),
			}
		}
	}
}
