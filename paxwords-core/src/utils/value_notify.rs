use parking_lot::Mutex;
use tokio::sync::Notify;

/// A simple wrapper around value, which allows waiting for value change in
/// async contexts.
#[derive(Debug)]
pub struct ValueNotify<V> {
	value: Mutex<V>,
	notify: Notify,
}

impl<V> ValueNotify<V> {
	/// Create new value.
	pub fn new(value: V) -> Self {
		Self {
			value: Mutex::new(value),
			notify: Notify::new(),
		}
	}

	/// Get current value.
	pub fn get(&self) -> V
	where
		V: Clone,
	{
		self.value.lock().clone()
	}

	/// Set current value.
	pub fn set(&self, value: V) -> V {
		let mut lock = self.value.lock();
		std::mem::replace(&mut *lock, value)
	}

	/// Set value with given function. The function shall not block.
	pub fn set_with(&self, f: impl FnOnce(&mut V)) {
		f(&mut *self.value.lock());
		self.notify.notify_one();
	}

	/// Compare and set current value.
	#[allow(clippy::result_unit_err)]
	pub fn compare_exchange(&self, current: &V, new: V, notify: bool) -> Result<(), ()>
	where
		V: PartialEq,
	{
		let mut lock = self.value.lock();
		if *lock == *current {
			*lock = new;
			if notify {
				self.notify.notify_one();
			}
			Ok(())
		} else {
			Err(())
		}
	}

	/// Wait until value is updated.
	pub async fn wait_change(&self) {
		self.notify.notified().await
	}
}
