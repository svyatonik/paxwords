use super::differences;

use libp2p::PeerId;
use paxwords_core::{
	Encrypted, Entry, EntryIndex, Error as CoreError, ErrorKind as CoreErrorKind, HashHalf,
	PeerState, utils::ValueNotify,
};
use std::sync::Arc;
use std::{collections::HashMap, io::Error as IoError};
use thiserror_context::Context;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
enum RequestStatus {
	Inactive,
	WaitingForResponse,
	Responded(Option<differences::Response>),
}

// a slightly hacky implementation of `PartialEq` that we only need in
// `ValueNotify::compare_exchange` call - we only care about variant, not
// about content
impl std::cmp::PartialEq for RequestStatus {
	fn eq(&self, other: &Self) -> bool {
		matches!(
			(self, other),
			(Self::Inactive, Self::Inactive)
				| (Self::WaitingForResponse, Self::WaitingForResponse)
				| (Self::Responded(..), Self::Responded(..))
		)
	}
}

/// A request that is being sent to provider.
pub struct ToProviderRequest {
	/// Provider peer id.
	pub peer_id: PeerId,
	/// A request itself.
	pub request: differences::Request,
}

/// A provider that shares the master password knowledge with us.
///
/// At any time there can be only one outbound request (here: call of this object' methods).
/// Second request will immediately fail.
#[derive(Clone)]
pub struct Provider {
	/// Provider peer id.
	peer_id: PeerId,
	/// A channel to send outbound requests.
	outbound_requests_sender: mpsc::Sender<ToProviderRequest>,
	/// Response receiver for the .
	current_response: Arc<ValueNotify<RequestStatus>>,
}

impl Provider {
	/// Return provider peer id.
	pub fn peer_id(&self) -> &PeerId {
		&self.peer_id
	}

	async fn make_request(
		&self,
		request: differences::Request,
	) -> Result<RequestStatus, CoreError> {
		// only one request at a time allowed for every provider
		self.current_response
			.compare_exchange(
				&RequestStatus::Inactive,
				RequestStatus::WaitingForResponse,
				false,
			)
			.map_err(|_| {
				CoreError::from(CoreErrorKind::PeerCommunicationError(IoError::other(
					"another request in progress",
				)))
			})?;

		// try to send request to the network for sending it over to the peer
		let request = ToProviderRequest {
			peer_id: self.peer_id,
			request,
		};
		if let Err(e) = self.outbound_requests_sender.try_send(request) {
			// failed => allow other requests to be restarted
			self.current_response.set(RequestStatus::Inactive);
			return Err(CoreError::from(CoreErrorKind::PeerCommunicationError(
				IoError::other(e),
			)));
		}

		// wait for the response
		self.current_response.wait_change().await;

		// let other requests to start
		let response = self.current_response.set(RequestStatus::Inactive);

		Ok(response)
	}
}

impl paxwords_core::Peer for Provider {
	async fn sync_state(&self) -> Result<PeerState, CoreError> {
		let response = self
			.make_request(differences::Request::State)
			.await
			.context("sending request in Provider::sync_state")?;
		match response {
			RequestStatus::Responded(Some(differences::Response::State(state))) => Ok(PeerState {
				entries_count: state.entries_count,
				l0_hash: state.l0_hash,
			}),
			_ => Err(CoreError::from(CoreErrorKind::PeerCommunicationError(
				IoError::other("unexpected response"),
			)))
			.context("receiving response in Provider::sync_state"),
		}
	}

	async fn l1_hashes(&self) -> Result<Vec<HashHalf>, CoreError> {
		let response = self
			.make_request(differences::Request::L1Hashes)
			.await
			.context("sending request in Provider::l1_hashes")?;
		match response {
			RequestStatus::Responded(Some(differences::Response::L1Hashes(hashes))) => Ok(hashes),
			_ => Err(CoreError::from(CoreErrorKind::PeerCommunicationError(
				IoError::other("unexpected response"),
			)))
			.context("receiving response in Provider::l1_hashes"),
		}
	}

	async fn l2_hashes(
		&self,
		l1_chunk_index: EntryIndex,
	) -> Result<Option<Vec<HashHalf>>, CoreError> {
		let response = self
			.make_request(differences::Request::L2Hashes(l1_chunk_index))
			.await
			.context("sending request in Provider::l2_hashes")?;
		match response {
			RequestStatus::Responded(Some(differences::Response::L2Hashes(hashes))) => Ok(hashes),
			_ => Err(CoreError::from(CoreErrorKind::PeerCommunicationError(
				IoError::other("unexpected response"),
			)))
			.context("receiving response in Provider::l2_hashes"),
		}
	}

	async fn entry_hashes(
		&self,
		l2_chunk_index: EntryIndex,
	) -> Result<Option<Vec<HashHalf>>, CoreError> {
		let response = self
			.make_request(differences::Request::EntryHashes(l2_chunk_index))
			.await
			.context("sending request in Provider::entry_hashes")?;
		match response {
			RequestStatus::Responded(Some(differences::Response::EntryHashes(hashes))) => {
				Ok(hashes)
			}
			_ => Err(CoreError::from(CoreErrorKind::PeerCommunicationError(
				IoError::other("unexpected response"),
			)))
			.context("receiving response in Provider::entry_hashes"),
		}
	}

	async fn entry(&self, index: EntryIndex) -> Result<Entry<Encrypted, Encrypted>, CoreError> {
		let response = self
			.make_request(differences::Request::Entry(index))
			.await
			.context("sending request in Provider::entry")?;
		match response {
			RequestStatus::Responded(Some(differences::Response::Entry(entry))) => Ok(*entry),
			_ => Err(CoreError::from(CoreErrorKind::PeerCommunicationError(
				IoError::other("unexpected response"),
			)))
			.context("receiving response in Provider::entry"),
		}
	}
}

/// A set of colnnected providers.
pub struct Providers {
	/// All active providers.
	alive: HashMap<PeerId, Provider>,
	/// Outbound requests sender.
	outbound_requests_sender: mpsc::Sender<ToProviderRequest>,
}

impl Providers {
	/// Create new providers set.
	pub fn new(outbound_requests_sender: mpsc::Sender<ToProviderRequest>) -> Self {
		Providers {
			alive: HashMap::new(),
			outbound_requests_sender,
		}
	}

	/// When remote provider has responded to our request.
	pub fn on_inbound_response(
		&mut self,
		peer_id: &PeerId,
		response: Option<differences::Response>,
	) {
		if let Some(provider) = self.alive.get(peer_id) {
			let _ = provider.current_response.compare_exchange(
				&RequestStatus::WaitingForResponse,
				RequestStatus::Responded(response),
				true,
			);
		}
	}

	/// Add provider to the set.
	pub fn add(&mut self, peer_id: PeerId) -> Option<Provider> {
		if self.alive.contains_key(&peer_id) {
			return None;
		}

		let provider = Provider {
			peer_id,
			outbound_requests_sender: self.outbound_requests_sender.clone(),
			current_response: Arc::new(ValueNotify::new(RequestStatus::Inactive)),
		};
		self.alive.insert(peer_id, provider.clone());
		Some(provider)
	}

	/// Remove provider from the set.
	pub fn remove(&mut self, peer_id: &PeerId) {
		if let Some(provider) = self.alive.remove(peer_id) {
			provider.current_response.set(RequestStatus::Inactive);
		}
	}

	/// Get provider from the set.
	pub fn get(&self, peer_id: &PeerId) -> Option<Provider> {
		self.alive.get(peer_id).cloned()
	}
}
