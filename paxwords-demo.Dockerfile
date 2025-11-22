# docker build --tag paxwords-demo:latest --file paxwords-demo.Dockerfile .
# docker run --init paxwords-demo:latest

FROM rust:1.91

WORKDIR /paxwords
COPY paxwords-core /paxwords/paxwords-core
COPY paxwords-core-fuzz /paxwords/paxwords-core-fuzz
COPY paxwords-demo /paxwords/paxwords-demo
COPY paxwords-demo-framework /paxwords/paxwords-demo-framework
COPY paxwords-sync /paxwords/paxwords-sync
COPY Cargo.lock /paxwords/Cargo.lock
COPY Cargo.toml /paxwords/Cargo.toml

RUN cargo build -p paxwords-demo --release

ENV RUST_BACKTRACE=full
ENV RUST_LOG=libp2p=info,hickory_proto=info,yamux=info,multistream_select=info,hickory_resolver=info,libp2p_pnet=info,keyring=info,debug

ENTRYPOINT [ "target/release/paxwords-demo", "--storage", "secrets" ]
