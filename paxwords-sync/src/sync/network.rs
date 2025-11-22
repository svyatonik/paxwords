use super::{
	differences,
	providers::{Provider, Providers},
};
use crate::{
	ProviderAddress, bincodec::bincode_config, local_entries::LocalEntries, sync::LocalPeer,
};

use bincode::Encode;
use libp2p::{
	Multiaddr, PeerId, Transport, autonat,
	futures::StreamExt,
	gossipsub, noise, pnet,
	request_response::{self, ProtocolSupport},
	swarm::{NetworkBehaviour, StreamProtocol, Swarm, SwarmEvent},
	tcp, yamux,
};
use paxwords_core::{LocalPeer as _, MasterPassword, utils::ValueNotify};
use std::{net::Ipv4Addr, time::Duration};
use tokio::sync::mpsc;
use tracing::instrument;

/// Sync protocol name used by paxwords.
const PAXWORDS_DIFFERENCES_PROTO_NAME: StreamProtocol = StreamProtocol::new("/paxwords/diff/1.0.0");

/// Time between two consequent sync state gossip messages are generated. If some
/// differences/entries exchanges are completed with an error, this is used as a
/// second chance for nodes to perform sync.
const REPUBLISH_SYNC_STATE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Our network behaviour.
#[derive(NetworkBehaviour)]
pub struct Network {
	/// Autonat to discover whether we're behind NAT.
	autonat: autonat::Behaviour,
	/// Differences protocol.
	differences: request_response::Behaviour<differences::Codec>,
	/// Gossipsub to send our state updates to other providers.
	gossipsub: gossipsub::Behaviour,
}

impl Network {
	/// Run finder network and search for providers of `required_key`.
	#[instrument(skip_all, name = "Network::run")]
	pub async fn run<HeaderV: Clone + Encode>(
		interface: Ipv4Addr,
		master: &MasterPassword,
		local_entries: &LocalEntries<HeaderV>,
		local_sync_address: &ValueNotify<Option<ProviderAddress>>,
		remote_sync_addresses: &mut mpsc::Receiver<ProviderAddress>,
		providers_sender: &mut mpsc::Sender<Provider>,
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
			differences: {
				let protocols = [(PAXWORDS_DIFFERENCES_PROTO_NAME, ProtocolSupport::Full)];
				let config = request_response::Config::default();
				request_response::Behaviour::new(protocols, config)
			},
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

		// prepare transport:noise for encryption + yamux for multiplexing
		// but here we're also using PSK (pre-shared key) here to ensure that only
		// authentic providers can join this network
		let pnet_transport = {
			let noise_config = noise::Config::new(&local_key)?;
			let yamux_config = yamux::Config::default();

			// generate key that is used to encrypt p2p communication. We are deriving it from
			// master key known to all authentic nodes
			const SALT: &[u8; 16] = b"paxwords_saltnet";
			let pre_shared_key = master.derive_key(SALT)?;

			tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
				.and_then(move |socket, _| {
					pnet::PnetConfig::new(pnet::PreSharedKey::new(*pre_shared_key))
						.handshake(socket)
				})
				.upgrade(libp2p::core::transport::upgrade::Version::V1)
				.authenticate(noise_config)
				.multiplex(yamux_config)
		};

		// libp2p swarm = network
		let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
			// use tokio runtime
			.with_tokio()
			// TCP-based transport: noise for encryption + yamux for multiplexing
			// we're using PSK (pre-shared key) here to ensure that only authentic providers
			// can use this network
			.with_other_transport(|_| pnet_transport)?
			// with DNS name resolving
			.with_dns()?
			// add Kademlia behavior (a set of protocols)
			.with_behaviour(|_| network)
			.expect("infallible")
			.build();

		tracing::info!("starting sync swarm {}", local_peer_id);

		// topic we're interested in
		let topic = "/entries/state-updated";
		let topic = gossipsub::Sha256Topic::new(topic);
		swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

		// start listening on given IPV4 interface + random port
		swarm.listen_on(
			libp2p::Multiaddr::empty()
				.with(libp2p::multiaddr::Protocol::Ip4(interface))
				.with(libp2p::multiaddr::Protocol::Tcp(0)),
		)?;

		fn send_status_update<HeaderV: Clone + Encode>(
			swarm: &mut Swarm<Network>,
			topic: &gossipsub::Sha256Topic,
			local_entries: &LocalEntries<HeaderV>,
		) -> Result<(), ()> {
			let Ok(sync_state) = local_entries.sync_state() else {
				tracing::debug!("failed to gossip our sync state: state is currently changing");
				return Err(());
			};

			tracing::debug!("going to gossip our sync state: {sync_state:?}");

			let sync_state: differences::PeerState = sync_state.into();
			let sync_state = match bincode::encode_to_vec(sync_state, bincode_config()) {
				Ok(sync_state) => sync_state,
				Err(e) => {
					tracing::debug!("failed to encode our sync state: {e:?}");
					return Err(());
				}
			};

			// it can fail immediately if there are no peers who're subscribed to this topic
			if let Err(e) = swarm
				.behaviour_mut()
				.gossipsub
				.publish(topic.clone(), sync_state)
			{
				tracing::debug!("failed to gossip our sync state: {e:?}");
				Err(())
			} else {
				Ok(())
			}
		}

		fn update_my_sync_address(
			my_peer_id: PeerId,
			my_sync_address: &mut Option<ProviderAddress>,
			address: Multiaddr,
			remove: bool,
		) {
			if my_sync_address.is_none() && remove {
				return;
			}

			// TODO: try to filter address here - it could be a loopback

			let mut my_sync_address_new =
				my_sync_address.take().unwrap_or_else(|| ProviderAddress {
					peer_id: my_peer_id,
					addresses: Vec::new(),
				});
			if remove {
				my_sync_address_new.addresses.retain(|x| *x != address);
			} else if !my_sync_address_new.addresses.contains(&address) {
				my_sync_address_new.addresses.push(address);
			}

			if !my_sync_address_new.addresses.is_empty() {
				*my_sync_address = Some(my_sync_address_new);
			}

			tracing::debug!("changed my sync listen address to: {my_sync_address:?}");
		}

		let (outbound_requests_sender, mut outbound_requests_receiver) = mpsc::channel(16);
		let mut providers = Providers::new(outbound_requests_sender);

		// leave some time for providers to be found
		let mut resend_state_updates =
			tokio_stream::wrappers::IntervalStream::new(tokio::time::interval_at(
				tokio::time::Instant::now() + Duration::from_secs(60),
				REPUBLISH_SYNC_STATE_INTERVAL,
			));

		loop {
			let event = tokio::select! {
				event = swarm.select_next_some() => event,
				_ = resend_state_updates.next() => {
					let _ = send_status_update(&mut swarm, &topic, local_entries);
					continue;
				}
				_ = local_entries.wait_change() => {
					tracing::debug!("entries are updated. Will be trying to gossip update");
					if send_status_update(&mut swarm, &topic, local_entries).is_ok() {
						resend_state_updates.as_mut().reset();
					}
					continue;
				}
				remote_provider_addresses = remote_sync_addresses.recv() => {
					if let Some(other_provider) = remote_provider_addresses {
						if other_provider.peer_id == local_peer_id {
							continue;
						}

						tracing::debug!("got new potential provider: {other_provider:?}");

						// TODO: `other_provider_addresses` may come from untrusted source and
						// it can overwrite valid addresses (that have came from valid providers)
						for address in other_provider.addresses {
							swarm.add_peer_address(other_provider.peer_id, address);
						}

						if !swarm.is_connected(&other_provider.peer_id) {
							if let Err(e) = swarm.dial(other_provider.peer_id) {
								tracing::debug!(
									"failed to dial potential provider {:?}: {:?}",
									other_provider.peer_id,
									e,
								);
							}
						} else {
							tracing::debug!(
								"already connected to potential provider {:?}",
								other_provider.peer_id,
							);
						}
					} else {
						tracing::debug!("their sync addresses channel has been closed");
						return Ok(());
					}
					continue;
				},
				outbound_request = outbound_requests_receiver.recv() => {
					if let Some(outbound_request) = outbound_request {
						tracing::info!(
							"sending request to remote provider {:?}: {:?}",
							outbound_request.peer_id,
							outbound_request.request,
						);

						swarm.behaviour_mut().differences
							.send_request(&outbound_request.peer_id, outbound_request.request);
					} else {
						tracing::debug!("outbound requests channel has been closed");
						return Ok(());
					}
					continue;
				},
			};

			match event {
				SwarmEvent::NewListenAddr { address, .. } => {
					tracing::info!("listening on {address:?}");
					local_sync_address.set_with(|my_listen_addr| {
						update_my_sync_address(local_peer_id, my_listen_addr, address, false)
					});
				}
				SwarmEvent::ExpiredListenAddr { address, .. } => {
					tracing::error!("listen address expired: {address:?}");
					local_sync_address.set_with(|my_listen_addr| {
						update_my_sync_address(local_peer_id, my_listen_addr, address, true)
					});
				}
				SwarmEvent::ListenerClosed {
					addresses, reason, ..
				} => {
					tracing::error!("listen {addresses:?} closed: {reason:?}");
					local_sync_address.set_with(|my_listen_addr| {
						for address in addresses {
							update_my_sync_address(local_peer_id, my_listen_addr, address, true)
						}
					});
				}

				SwarmEvent::ExternalAddrConfirmed { address, .. } => {
					tracing::info!("external address confirmed: {address:?}");
					local_sync_address.set_with(|my_listen_addr| {
						update_my_sync_address(local_peer_id, my_listen_addr, address, false)
					});
				}
				SwarmEvent::ExternalAddrExpired { address } => {
					tracing::info!("external address expired: {address:?}");
					local_sync_address.set_with(|my_listen_addr| {
						update_my_sync_address(local_peer_id, my_listen_addr, address, true)
					});
				}

				SwarmEvent::ConnectionEstablished { peer_id, .. } => {
					// connection to other peer has been successfully established. Since we
					// use pnet transport (with pre-shared key), it means that handshake has
					// been successful and we know for sure that this provider is authentic.
					// So we may report it to callers.
					if let Some(provider) = providers.add(peer_id) {
						tracing::debug!("provider confirmed: {peer_id:?}");

						swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
						if providers_sender.try_send(provider).is_err() {
							tracing::debug!(
								"failed to send new provider {peer_id:?} to providers channel"
							);

							// forget provider - we'll reconnect later
							providers.remove(&peer_id);
							// we don't care if connection has been already closed
							let _ = swarm.disconnect_peer_id(peer_id);
						}
					}
				}
				SwarmEvent::ConnectionClosed {
					peer_id,
					num_established,
					..
				} => {
					// forget provider (it it was a provider)
					if num_established == 0 {
						tracing::debug!("provider disconnected: {:?}", peer_id);
						providers.remove(&peer_id);
					}
				}

				SwarmEvent::IncomingConnection { send_back_addr, .. } => {
					tracing::debug!(
						"starting negotiating incoming connection with {send_back_addr:?}"
					);
				}
				SwarmEvent::IncomingConnectionError { peer_id, error, .. } => {
					tracing::debug!(
						"incoming connection with {peer_id:?} has failed with: {error:?}"
					);
				}
				SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
					tracing::debug!(
						"outgoing connection with {peer_id:?} has failed with: {error:?}"
					);
				}

				SwarmEvent::Behaviour(NetworkEvent::Differences(
					request_response::Event::Message {
						peer,
						message:
							request_response::Message::Request {
								request, channel, ..
							},
						..
					},
				)) => {
					tracing::debug!("got request from provider {peer:?}: {request:?}");
					match local_entries.process_inbound_request(request) {
						Ok(response) => {
							tracing::debug!("sending response to provider {peer:?}: {response:?}");
							if let Err(e) = swarm
								.behaviour_mut()
								.differences
								.send_response(channel, response)
							{
								tracing::debug!(
									"failed to send response to provider {peer:?}: {e:?}"
								);
							}
						}
						Err(e) => {
							tracing::debug!(
								"failed to process incoming request from {peer:?}: {e:?}"
							);
						}
					}
				}
				SwarmEvent::Behaviour(NetworkEvent::Differences(
					request_response::Event::Message {
						peer,
						message: request_response::Message::Response { response, .. },
						..
					},
				)) => {
					tracing::debug!("got response from provider {peer:?}: {response:?}");
					providers.on_inbound_response(&peer, Some(response));
				}
				SwarmEvent::Behaviour(NetworkEvent::Differences(
					request_response::Event::OutboundFailure { peer, error, .. },
				)) => {
					tracing::debug!("outbound message to provider {peer:?} failed: {error:?}");
					providers.on_inbound_response(&peer, None);
				}
				SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Message {
					message,
					..
				})) => {
					let Some(peer_id) = message.source else {
						// the message sender is unknown
						tracing::debug!("ignoring sync state gossip message from unknown source");
						continue;
					};
					let Some(provider) = providers.get(&peer_id) else {
						// the provider is unknown to us => do nothing
						tracing::debug!(
							"ignoring sync state gossip message from provider we do not trust yet: {:?}",
							message.source,
						);
						continue;
					};

					tracing::debug!(
						"received sync state gossip message from {:?}",
						message.source
					);

					// we've got (hopefully sync state) of other peer
					let peer_sync_state = bincode::decode_from_slice::<differences::PeerState, _>(
						&message.data,
						bincode_config(),
					);

					// if we've failed to decode address, just log it
					let peer_sync_state = match peer_sync_state {
						Ok(peer_sync_state) => peer_sync_state,
						Err(e) => {
							tracing::debug!(
								"got bad sync state from peer {:?}: {e:?}",
								message.source
							);
							continue;
						}
					};

					let Ok(local_sync_state) = local_entries.sync_state() else {
						// our state is currently changind => do nothing
						tracing::debug!(
							"ignoring sync state gossip message from provider {:?}: our entries are changing",
							message.source,
						);
						continue;
					};
					if peer_sync_state.0 == local_sync_state.into() {
						// states are the same => do nothing
						tracing::debug!(
							"ignoring sync state gossip message from provider {:?}: our entries are the same",
							message.source,
						);
						continue;
					}

					tracing::debug!(
						"provider {:?} has different entries. Trying to fetch differences",
						peer_id
					);
					if let Err(e) = providers_sender.try_send(provider) {
						tracing::debug!("failed to send provider to sync process: {e:?}");
					}
				}
				_ => (),
			}
		}
	}
}
