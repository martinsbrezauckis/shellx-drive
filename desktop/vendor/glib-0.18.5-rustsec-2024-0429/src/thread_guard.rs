// Take a look at the license at the top of the repository in the LICENSE file.

use std::{
    mem, ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
fn next_thread_id() -> usize {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

// rustdoc-stripper-ignore-next
/// Returns a unique ID for the current thread.
///
/// Actual thread IDs can be reused by the OS once the old thread finished.
/// This works around ambiguity created by ID reuse by using a separate TLS counter for threads.
pub fn thread_id() -> usize {
    thread_local!(static THREAD_ID: usize = next_thread_id());
    THREAD_ID.with(|&x| x)
}

// rustdoc-stripper-ignore-next
/// Thread guard that only gives access to the contained value on the thread it was created on.
pub struct ThreadGuard<T> {
    thread_id: usize,
    value: mem::ManuallyDrop<T>,
}

impl<T> ThreadGuard<T> {
    // rustdoc-stripper-ignore-next
    /// Create a new thread guard around `value`.
    ///
    /// The thread guard ensures that access to the value is only allowed from the thread it was
    /// created on, and otherwise panics.
    ///
    /// The thread guard implements the `Send` trait even if the contained value does not.
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            thread_id: thread_id(),
            value: mem::ManuallyDrop::new(value),
        }
    }

    // rustdoc-stripper-ignore-next
    /// Return a reference to the contained value from the thread guard.
    ///
    /// # Panics
    ///
    /// This function panics if called from a different thread than where the thread guard was
    /// created.
    #[inline]
    pub fn get_ref(&self) -> &T {
        assert!(
            self.thread_id == thread_id(),
            "Value accessed from different thread than where it was created"
        );

        &self.value
    }

    // rustdoc-stripper-ignore-next
    /// Return a mutable reference to the contained value from the thread guard.
    ///
    /// # Panics
    ///
    /// This function panics if called from a different thread than where the thread guard was
    /// created.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        assert!(
            self.thread_id == thread_id(),
            "Value accessed from different thread than where it was created"
        );

        &mut self.value
    }

    // rustdoc-stripper-ignore-next
    /// Return the contained value from the thread guard.
    ///
    /// # Panics
    ///
    /// This function panics if called from a different thread than where the thread guard was
    /// created.
    #[inline]
    pub fn into_inner(self) -> T {
        assert!(
            self.thread_id == thread_id(),
            "Value accessed from different thread than where it was created"
        );

        unsafe { mem::ManuallyDrop::into_inner(ptr::read(&mem::ManuallyDrop::new(self).value)) }
    }

    // rustdoc-stripper-ignore-next
    /// Returns `true` if the current thread owns the value, i.e. it can be accessed safely.
    #[inline]
    pub fn is_owner(&self) -> bool {
        self.thread_id == thread_id()
    }
}

impl<T> Drop for ThreadGuard<T> {
    #[inline]
    fn drop(&mut self) {
        assert!(
            self.thread_id == thread_id(),
            "Value dropped on a different thread than where it was created"
        );
        // A failed thread check must not run the value's destructor while
        // unwinding. On the owning thread, destroy it exactly once.
        unsafe { mem::ManuallyDrop::drop(&mut self.value) };
    }
}

unsafe impl<T> Send for ThreadGuard<T> {}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, rc::Rc, sync::Arc};

    use super::*;

    struct NonSendDropCounter {
        drops: Arc<AtomicUsize>,
        _non_send: PhantomData<Rc<()>>,
    }

    impl Drop for NonSendDropCounter {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter(drops: &Arc<AtomicUsize>) -> NonSendDropCounter {
        NonSendDropCounter {
            drops: drops.clone(),
            _non_send: PhantomData,
        }
    }

    #[test]
    fn foreign_thread_drop_does_not_destroy_non_send_value_during_unwind() {
        let drops = Arc::new(AtomicUsize::new(0));
        let guard = ThreadGuard::new(counter(&drops));
        assert!(std::thread::spawn(move || drop(guard)).join().is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn owner_thread_drop_destroys_value_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        drop(ThreadGuard::new(counter(&drops)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn into_inner_transfers_single_drop_to_returned_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let value = ThreadGuard::new(counter(&drops)).into_inner();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(value);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn owner_accessors_preserve_value() {
        let mut guard = ThreadGuard::new(String::from("before"));
        assert!(guard.is_owner());
        assert_eq!(guard.get_ref(), "before");
        guard.get_mut().push_str(" after");
        assert_eq!(guard.into_inner(), "before after");
    }
}
