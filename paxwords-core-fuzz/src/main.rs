use paxwords_core::{
	Entries, MasterPassword, apply_remote_entries, find_differences, retrieve_entries,
};
use paxwords_demo_framework::{MergeAlgorithm, Randomness};
use rand::Rng;
use std::{path::PathBuf, sync::Arc};
use tempdir::TempDir;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() {
	let _ = tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.with_writer(std::io::stderr)
		.try_init();

	let mut rng = rand::rng();
	loop {
		// random path

		let seed = rng.random::<u64>();
		let limit = rng.random::<u32>() as usize % 10_000;
		let mut rng = Randomness::limited(seed, limit);
		println!("running for seed={seed} with limit={limit}");

		// initialization

		let master =
			Arc::new(MasterPassword::from_password_secret("admin-password".into()).unwrap());

		let dir = TempDir::new("paxwords-fuzz").unwrap();
		let mut storage1: PathBuf = dir.path().into();
		let mut storage2: PathBuf = storage1.clone();
		storage1.push("storage1");
		storage2.push("storage2");

		let mut entries1 = Entries::new(&storage1, master.clone()).unwrap();
		let mut entries2 = Entries::new(&storage2, master.clone()).unwrap();

		println!("...initialized");

		// updates

		while !rng.is_done() {
			let entries = if rng.maybe_next_u16().unwrap() < u16::MAX / 2 {
				&mut entries1
			} else {
				&mut entries2
			};

			paxwords_demo_framework::perform_operation(&mut rng, entries);
		}

		println!("...updated");

		// sync

		let differences1 = find_differences(
			&entries1.flushed_entries().upgrade().unwrap(),
			&entries2.flushed_entries().upgrade().unwrap(),
		)
		.await
		.unwrap();
		let differences2 = find_differences(
			&entries2.flushed_entries().upgrade().unwrap(),
			&entries1.flushed_entries().upgrade().unwrap(),
		)
		.await
		.unwrap();
		let remote_entries1 =
			retrieve_entries(entries2.flushed_entries().upgrade().unwrap(), differences1)
				.collect::<Result<Vec<_>, _>>()
				.await
				.unwrap();
		let remote_entries2 =
			retrieve_entries(entries1.flushed_entries().upgrade().unwrap(), differences2)
				.collect::<Result<Vec<_>, _>>()
				.await
				.unwrap();
		let batch1 = apply_remote_entries::<MergeAlgorithm, _, _>(
			&master,
			&entries1.unflushed_entries().upgrade().unwrap(),
			remote_entries1
				.into_iter()
				.map(|(_, entry)| entry)
				.collect(),
		)
		.unwrap();
		let batch2 = apply_remote_entries::<MergeAlgorithm, _, _>(
			&master,
			&entries2.unflushed_entries().upgrade().unwrap(),
			remote_entries2
				.into_iter()
				.map(|(_, entry)| entry)
				.collect(),
		)
		.unwrap();
		entries1.apply_batch(batch1).unwrap();
		entries2.apply_batch(batch2).unwrap();

		println!("...synced");

		// verify that entries are the same

		let differences1 = find_differences(
			&entries1.flushed_entries().upgrade().unwrap(),
			&entries2.flushed_entries().upgrade().unwrap(),
		)
		.await
		.unwrap();
		let differences2 = find_differences(
			&entries2.flushed_entries().upgrade().unwrap(),
			&entries1.flushed_entries().upgrade().unwrap(),
		)
		.await
		.unwrap();
		if !differences1.is_empty() || !differences2.is_empty() {
			println!("fails for seed: {seed}");
			return;
		}
	}
}
