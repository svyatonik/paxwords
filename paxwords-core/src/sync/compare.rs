use super::{LocalPeer, Peer};
use crate::{EntryIndex, Error, ErrorKind};

/// Find all entries that are different/missing in local storage (represented by [me])
/// and some other (potentially remote) peer. This operation is not symmetric - e.g.
/// if `me` has 10 entries and `peer` has 0 entries, the difference is empty vec.
/// But when called on `peer`, the difference is all missing entries.
///
/// The goal of entries sync protocol is to minimize number of network bytes sent during the sync.
/// Main assumptions:
///
/// - there can be at most `65_536` entries in the [crate::Entries] (this is dictated by the
///   unique [crate::Id] backed by the `u16`);
///
/// - our state is **mostly** static. Most of changes (append and update) are rare. So most
///   of times peers will have the same state.
///
/// So most of times states are the same. Let's split all our entries into 256 level-1 (L1)
/// chunks, with 256 entries each. Every L1 chunk then may be identified with the single [Hash]
/// and the whole state may be identified with a single [Hash] computed as hash of concatenated
/// L1 chunk hashes. The happy case for two peers is when those hashes match, meaning that their
/// states are the same.
///
/// But if those hashes are different, then we may request L1 chunk hashes (256 hashes) from
/// the peer and find the different L1 chunks by comparing with our hashes. Then we split every L1
/// chunk into 16 level-2 (L2) chunks with 16 entries each. And then we may again compute L2
/// hash for those L2 chunks and find those L2 chunks that differ. Finally, once we've found
/// different L2 chunks, we may find which entries are different by exchanging hashes of entries
/// of different L2 chunks.
pub async fn find_differences(
	me: &impl LocalPeer,
	peer: &impl Peer,
) -> Result<Vec<EntryIndex>, Error> {
	let mut result = Vec::<EntryIndex>::new();

	// get sync state
	let my_state = me.sync_state()?;
	let peer_state = peer.sync_state().await?;

	// if state is the same, there are no differences
	if my_state == peer_state {
		return Ok(result);
	}

	// ok, we know that something is different. Let's:
	// 1) check all L1 hashes that both peers have;
	// 2) for every different L1 chunk, get all L2 hashes within;
	// 3) for every different L2 chunk, get all entry hashes within.
	// 4) entries with different hashes are different
	let my_l1_hashes = me.l1_hashes()?;
	let peer_l1_hashes = peer.l1_hashes().await?;
	for (l1_index, (my_l1_hash, peer_l1_hash)) in
		my_l1_hashes.iter().zip(peer_l1_hashes.iter()).enumerate()
	{
		if my_l1_hash == peer_l1_hash {
			continue;
		}

		let l1_entry_index: EntryIndex = (l1_index as u16).into();
		let Some(my_l2_hashes) = me.l2_hashes(l1_entry_index)? else {
			// we can't compare L1 that we do not have
			break;
		};

		let peer_l2_hashes = peer.l2_hashes(l1_entry_index).await?.ok_or_else(|| {
			Error::from(ErrorKind::PeerCommunicationError(std::io::Error::other(
				format!("failed to retrive l2_hashes({l1_entry_index:?}) from remote peer"),
			)))
		})?;
		for (l2_offset, (my_l2_hash, peer_l2_hash)) in
			my_l2_hashes.iter().zip(peer_l2_hashes.iter()).enumerate()
		{
			if my_l2_hash == peer_l2_hash {
				continue;
			}

			let l2_index = l1_index * 16 + l2_offset;
			let l2_entry_index: EntryIndex = (l2_index as u16).into();
			let Some(my_entry_hashes) = me.entry_hashes(l2_entry_index)? else {
				// we can't compare L2 that we do not have
				break;
			};

			let peer_entry_hashes = peer.entry_hashes(l2_entry_index).await?.ok_or_else(|| {
				Error::from(ErrorKind::PeerCommunicationError(std::io::Error::other(
					format!("failed to retrive entry_hashes({l2_entry_index:?}) from remote peer"),
				)))
			})?;
			for (entry_offset, (my_entry_hash, peer_entry_hash)) in my_entry_hashes
				.iter()
				.zip(peer_entry_hashes.iter())
				.enumerate()
			{
				if my_entry_hash == peer_entry_hash {
					continue;
				}

				let entry_index = EntryIndex::from((l2_index * 16 + entry_offset) as u16);
				tracing::debug!(
					"found different entry {entry_index:?}: local_hash={:?}, remote_hash={:?}",
					my_entry_hash,
					peer_entry_hash
				);
				result.push(entry_index);
			}
		}
	}

	// also all new entries, with indices larger than `my_state.entries_count`, are 'different'
	let new_range_begin: u16 = my_state.entries_count.into();
	let new_range_end: u16 = peer_state.entries_count.into();
	let new_entries = new_range_begin..new_range_end;
	if !new_entries.is_empty() {
		tracing::debug!(
			"also found new 'different' entries: {:?}..{:?}",
			my_state.entries_count,
			peer_state.entries_count
		);
		result.extend(new_entries.map(EntryIndex::from));
	}

	Ok(result)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Entries, test_utils::*};

	#[tokio::test]
	async fn find_differences_works() {
		with_tempdir(|path| async move {
			let mut path1 = path.clone();
			path1.pop();
			path1.push("paxwords1");
			let mut path2 = path;
			path2.pop();
			path2.push("paxwords2");

			// both states are empty
			let mut entries1 = Entries::<TestOrder>::new(&path1, master()).unwrap();
			let mut entries2 = Entries::<TestOrder>::new(&path2, master()).unwrap();

			// both states are the same => no differrences
			assert_eq!(
				find_differences(
					entries1.flushed_entries_ref(),
					entries2.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![]
			);
			assert_eq!(
				find_differences(
					entries2.flushed_entries_ref(),
					entries1.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![]
			);

			// add entry to state1
			entries1.insert(plain_entry(0)).unwrap();
			entries1.flush().unwrap();

			// when calling on peer1: no differences
			assert_eq!(
				find_differences(
					entries1.flushed_entries_ref(),
					entries2.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![]
			);
			// when calling on peer2: the difference is entry#0
			assert_eq!(
				find_differences(
					entries2.flushed_entries_ref(),
					entries1.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![0u16.into()]
			);

			// add entry to state1
			entries2.insert(plain_entry(0)).unwrap();
			entries2.flush().unwrap();

			// both states are the same => no differrences
			assert_eq!(
				find_differences(
					entries1.flushed_entries_ref(),
					entries2.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![]
			);
			assert_eq!(
				find_differences(
					entries2.flushed_entries_ref(),
					entries1.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![]
			);

			// now change entry at peer2
			entries2
				.update(
					entries2.unflushed_entries_ref()[0].clone(),
					plain_entry_with_key(0, 1),
				)
				.unwrap();
			entries2.flush().unwrap();

			// when calling on peer1: the difference is entry#0
			assert_eq!(
				find_differences(
					entries1.flushed_entries_ref(),
					entries2.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![0u16.into()]
			);
			// when calling on peer2: the difference is entry#0
			assert_eq!(
				find_differences(
					entries2.flushed_entries_ref(),
					entries1.flushed_entries_ref()
				)
				.await
				.unwrap(),
				vec![0u16.into()]
			);
		})
		.await;
	}
}
