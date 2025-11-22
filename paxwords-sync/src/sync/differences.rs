use crate::bincodec::BinCodec;

use bincode::{Decode, Encode};
use paxwords_core::{Encrypted, Entry, EntryIndex, HashHalf};
use serde::{Deserialize, Serialize};

/// Differences protocol codec.
pub type Codec = BinCodec<Request, Response>;

/// State of peer entries storage.
#[derive(Clone, Debug, Decode, Deserialize, Encode, Eq, PartialEq, Serialize)]
pub struct PeerState {
	/// Total number of entries in the storage.
	pub entries_count: EntryIndex,
	/// L0 entries state hash.
	pub l0_hash: HashHalf,
}

/// Differences protocol requests.
#[derive(Clone, Debug, Decode, Deserialize, Encode, Eq, PartialEq, Serialize)]
pub enum Request {
	/// Request peer state.
	State,
	/// Request all L1 hashes.
	L1Hashes,
	/// Request L2 hashes of given L1 chunk.
	L2Hashes(EntryIndex),
	/// Request hashes of entries within given L2 chunk.
	EntryHashes(EntryIndex),
	/// Request entry.
	Entry(EntryIndex),
}

/// Differences protocol responses.
#[derive(Clone, Decode, Deserialize, Encode, Serialize)]
pub enum Response {
	/// Peer state response.
	State(PeerState),
	/// L1 hashes response.
	L1Hashes(Vec<HashHalf>),
	/// L2 hashes response.
	L2Hashes(Option<Vec<HashHalf>>),
	/// Entry hashes reponse.
	EntryHashes(Option<Vec<HashHalf>>),
	/// Entry response.
	Entry(Box<Entry<Encrypted, Encrypted>>),
}

impl std::fmt::Debug for Response {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match *self {
			Self::State(ref state) => write!(f, "State({state:?})"),
			Self::L1Hashes(_) => write!(f, "L1Hashes(<...>"),
			Self::L2Hashes(_) => write!(f, "L2Hashes(<...>"),
			Self::EntryHashes(_) => write!(f, "EntryHashes(<...>"),
			Self::Entry(_) => write!(f, "Entry(<...>"),
		}
	}
}

impl From<paxwords_core::PeerState> for PeerState {
	fn from(state: paxwords_core::PeerState) -> PeerState {
		PeerState {
			entries_count: state.entries_count,
			l0_hash: state.l0_hash,
		}
	}
}

/// An extension over [paxwords_core::LocalPeer] that works directly with our requests
/// and responses.
pub trait LocalPeer: paxwords_core::LocalPeer {
	/// Process differences protocol request.
	fn process_inbound_request(&self, request: Request) -> Result<Response, paxwords_core::Error> {
		match request {
			Request::State => {
				let state = self.sync_state()?;
				Ok(Response::State(PeerState {
					entries_count: state.entries_count,
					l0_hash: state.l0_hash,
				}))
			}
			Request::L1Hashes => Ok(Response::L1Hashes(self.l1_hashes()?)),
			Request::L2Hashes(l1_chunk_index) => {
				Ok(Response::L2Hashes(self.l2_hashes(l1_chunk_index)?))
			}
			Request::EntryHashes(l2_chunk_index) => {
				Ok(Response::EntryHashes(self.entry_hashes(l2_chunk_index)?))
			}
			Request::Entry(index) => Ok(Response::Entry(Box::new(self.entry(index)?))),
		}
	}
}

impl<T: paxwords_core::LocalPeer> LocalPeer for T {}
