use bincode::{Decode, Encode};
use libp2p::{StreamProtocol, futures::prelude::*, request_response::Codec};
use serde::{Deserialize, Serialize};
use std::{io, marker::PhantomData};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};

// the only reason why we need `serde` everywhere is `AsyncBincode*`

#[derive(Clone)]
pub struct BinCodec<Req, Resp> {
	_phantom: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> Default for BinCodec<Req, Resp> {
	fn default() -> Self {
		Self {
			_phantom: PhantomData,
		}
	}
}

#[async_trait::async_trait]
impl<Req, Resp> Codec for BinCodec<Req, Resp>
where
	Req: Serialize + for<'de> Deserialize<'de> + Decode<()> + Encode + Send + 'static,
	Resp: Serialize + for<'de> Deserialize<'de> + Decode<()> + Encode + Send + 'static,
{
	type Protocol = StreamProtocol;
	type Request = Req;
	type Response = Resp;

	async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
	where
		T: AsyncRead + Unpin + Send,
	{
		let tokio_io = io.compat();
		futures::pin_mut!(tokio_io);
		let mut reader = async_bincode::tokio::AsyncBincodeReader::from(&mut tokio_io).fuse();
		reader
			.next()
			.await
			.ok_or_else(|| std::io::Error::other("AsyncBincodeReader::next has returned none"))?
			.map_err(std::io::Error::other)
	}

	async fn read_response<T>(
		&mut self,
		_: &Self::Protocol,
		io: &mut T,
	) -> io::Result<Self::Response>
	where
		T: AsyncRead + Unpin + Send,
	{
		let tokio_io = io.compat();
		futures::pin_mut!(tokio_io);
		let mut reader = async_bincode::tokio::AsyncBincodeReader::from(&mut tokio_io).fuse();
		reader
			.next()
			.await
			.ok_or_else(|| std::io::Error::other("AsyncBincodeReader::next has returned none"))?
			.map_err(std::io::Error::other)
	}

	async fn write_request<T>(
		&mut self,
		_: &Self::Protocol,
		io: &mut T,
		req: Self::Request,
	) -> io::Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		let tokio_io = io.compat_write();
		futures::pin_mut!(tokio_io);
		let mut writer = async_bincode::tokio::AsyncBincodeWriter::from(tokio_io).for_async();
		writer.send(req).await.map_err(std::io::Error::other)
	}

	async fn write_response<T>(
		&mut self,
		_: &Self::Protocol,
		io: &mut T,
		resp: Self::Response,
	) -> io::Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		let tokio_io = io.compat_write();
		futures::pin_mut!(tokio_io);
		let mut writer = async_bincode::tokio::AsyncBincodeWriter::from(tokio_io).for_async();
		writer.send(resp).await.map_err(std::io::Error::other)
	}
}

pub fn bincode_config() -> impl bincode::config::Config {
	bincode::config::standard()
		.with_little_endian()
		.with_fixed_int_encoding()
		.with_limit::<65_536>()
}
