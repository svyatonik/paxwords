use super::Peer;
use crate::{
	EntryIndex, Error,
	types::{Encrypted, Entry},
};

use tokio_stream::Stream;

/// Retrive all requested entries from remote peer, one by one.
pub fn retrieve_entries(
	peer: impl Peer,
	indices: Vec<EntryIndex>,
) -> impl Stream<Item = Result<(EntryIndex, Entry<Encrypted, Encrypted>), Error>> + Unpin {
	// we won't be able to apply non-consequent entries => retrieve until first error
	Box::pin(futures::stream::unfold(
		(peer, 0, indices),
		|(peer, index, indices)| async move {
			let entry_index = *indices.get(index)?;
			match peer.entry(entry_index).await {
				Ok(entry) => Some((Ok((entry_index, entry)), (peer, index + 1, indices))),
				Err(e) => {
					// error here is not critical - we still may apply previous entries
					tracing::debug!(
						"failed to retrive entry {entry_index:?} from remote peer: {e:?}"
					);
					None
				}
			}
		},
	))
}
