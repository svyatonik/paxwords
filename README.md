A prototype of password manager that is able to sync and merge its databases from different
devices without centralized server and zero configuration. Sync only works if devices are
reachable with regular [`libp2p`](https://github.com/libp2p/rust-libp2p) techniques (like
mDNS, Kademlia with IPFS nodes, AutoNAT and Identify). Two `libp2p` swarms are used: one to
find other 'providers' (i.e. other instances of `paxwords` sharing the same 'master password')
and another one to exchange password entries. The latter uses
[`pnet`](https://github.com/libp2p/rust-libp2p/tree/master/transports/pnet) transport
for communication, so nodes that do not know the 'master password' won't be able to connect.
It doesn't protect from malicious peers that know this password, but that's out of this
demo scope.

Repository structure:

- [`paxwords-core`](./paxwords-core) is a crate that contains key primitives of password
  manager:
  - `paxwords_core::MasterPassword` is a 'master password' representation;
  - `paxwords_core::Entries` is a set of entries. Every entry is a header and body. Entries
    are stored in local file in encrypted form. While in memory, most of time body is
    stored encrypted and header is stored as plain data;
  - `paxwords_core::EntriesState`, `paxwords_core::Peer`, `paxwords_core::LocalPeeer`,
    `paxwords_core::find_differences`, `paxwords_core::retrieve_entries` and
    `paxwords_core::apply_remote_entries` are used in synchronization;
  - `paxwords_core::utils::event_loop` is an example of how real password manager may be
    organized;

- [`paxwords-sync`](./paxwords-sync) is a crate that performs sync over network;

- [`paxwords-demo`](./paxwords-demo) and [`paxwords-demo-framework`](./paxwords-demo-framework)
  is a simple console app that randomly creates entries and syncs them over network;

- [`paxwords-core-fuzz`](./paxwords-core-fuzz) is a fuzzer (that is not using any fuzz crates
  though) for sync process.

There's a [dockerfile](./paxwordmgr-demo.Dockerfile) for demo app and
[docker-compose.yml](./docker-compose.yml) that shows it all in action. However, it is more
interesting to run demo app on separate devices from different networks and watch them
trying to find each other.

The whole this thing is made for fun, not for production. Not audited and not well tested.
