// Take a look at the license at the top of the repository in the LICENSE file.

use std::{future::Future, panic, ptr};

use futures_channel::oneshot;

use crate::translate::*;

#[derive(Debug)]
#[doc(alias = "GThreadPool")]
pub struct ThreadPool(ptr::NonNull<ffi::GThreadPool>);

unsafe impl Send for ThreadPool {}
unsafe impl Sync for ThreadPool {}

// rustdoc-stripper-ignore-next
/// A handle to a thread running on a [`ThreadPool`].
///
/// Like [`std::thread::JoinHandle`] for a GLib thread. The return value from the task can be
/// retrieved by calling [`ThreadHandle::join`]. Dropping the handle "detaches" the thread,
/// allowing it to complete but discarding the return value.
#[derive(Debug)]
pub struct ThreadHandle<T> {
    rx: std::sync::mpsc::Receiver<std::thread::Result<T>>,
}

impl<T> ThreadHandle<T> {
    // rustdoc-stripper-ignore-next
    /// Waits for the associated thread to finish.
    ///
    /// Blocks until the associated thread returns. Returns `Ok` with the value returned from the
    /// thread, or `Err` if the thread panicked. This function will return immediately if the
    /// associated thread has already finished.
    #[inline]
    pub fn join(self) -> std::thread::Result<T> {
        self.rx.recv().unwrap()
    }
}

fn thread_pool_error(error: *mut ffi::GError, message: &str) -> crate::Error {
    unsafe {
        if error.is_null() {
            from_glib_full(ffi::g_error_new_literal(
                ffi::g_thread_error_quark(),
                ffi::G_THREAD_ERROR_AGAIN,
                message.to_glib_none().0,
            ))
        } else {
            from_glib_full(error)
        }
    }
}

fn checked_thread_limit(max_threads: Option<u32>, exclusive: bool) -> Result<i32, crate::Error> {
    match max_threads {
        Some(value) => i32::try_from(value).map_err(|_| {
            thread_pool_error(ptr::null_mut(), "Thread limit exceeds GLib's signed range")
        }),
        None if exclusive => Err(thread_pool_error(
            ptr::null_mut(),
            "An exclusive thread pool requires a finite thread limit",
        )),
        None => Ok(-1),
    }
}

impl ThreadPool {
    #[doc(alias = "g_thread_pool_new")]
    pub fn shared(max_threads: Option<u32>) -> Result<Self, crate::Error> {
        let max_threads = checked_thread_limit(max_threads, false)?;
        unsafe {
            let mut err = ptr::null_mut();
            let pool = ffi::g_thread_pool_new(
                Some(spawn_func),
                ptr::null_mut(),
                max_threads,
                ffi::GFALSE,
                &mut err,
            );
            Self::from_created_pool(pool, err)
        }
    }

    #[doc(alias = "g_thread_pool_new")]
    pub fn exclusive(max_threads: u32) -> Result<Self, crate::Error> {
        let max_threads = checked_thread_limit(Some(max_threads), true)?;
        unsafe {
            let mut err = ptr::null_mut();
            let pool = ffi::g_thread_pool_new(
                Some(spawn_func),
                ptr::null_mut(),
                max_threads,
                ffi::GTRUE,
                &mut err,
            );
            Self::from_created_pool(pool, err)
        }
    }

    unsafe fn from_created_pool(
        pool: *mut ffi::GThreadPool,
        error: *mut ffi::GError,
    ) -> Result<Self, crate::Error> {
        if !error.is_null() {
            // GLib can return a partial pool when starting exclusive workers
            // fails. No tasks have been queued before this constructor returns.
            if !pool.is_null() {
                ffi::g_thread_pool_free(pool, ffi::GTRUE, ffi::GTRUE);
            }
            return Err(thread_pool_error(
                error,
                "GLib could not create a thread pool",
            ));
        }
        ptr::NonNull::new(pool).map(ThreadPool).ok_or_else(|| {
            thread_pool_error(ptr::null_mut(), "GLib could not create a thread pool")
        })
    }

    #[doc(alias = "g_thread_pool_push")]
    pub fn push<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(
        &self,
        func: F,
    ) -> Result<ThreadHandle<T>, crate::Error> {
        self.push_with(func, |pool, data, error| unsafe {
            from_glib(ffi::g_thread_pool_push(pool, data, error))
        })
    }

    fn push_with<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(
        &self,
        func: F,
        push: impl FnOnce(*mut ffi::GThreadPool, ffi::gpointer, *mut *mut ffi::GError) -> bool,
    ) -> Result<ThreadHandle<T>, crate::Error> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        unsafe {
            let func: Box<dyn FnOnce() + Send + 'static> = Box::new(move || {
                let _ = tx.send(panic::catch_unwind(panic::AssertUnwindSafe(func)));
            });
            let func = Box::new(func);
            let mut err = ptr::null_mut();

            let func = Box::into_raw(func);
            let ret = push(self.0.as_ptr(), func as *mut _, &mut err);
            if ret {
                Ok(ThreadHandle { rx })
            } else {
                // GLib queues the item even if starting a worker fails. The
                // queued callback remains GLib's owner on both outcomes.
                if err.is_null() {
                    Err(from_glib_full(ffi::g_error_new_literal(
                        ffi::g_thread_error_quark(),
                        ffi::G_THREAD_ERROR_AGAIN,
                        "GLib could not start a pool worker".to_glib_none().0,
                    )))
                } else {
                    Err(from_glib_full(err))
                }
            }
        }
    }

    pub fn push_future<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(
        &self,
        func: F,
    ) -> Result<impl Future<Output = std::thread::Result<T>> + Send + Sync + 'static, crate::Error>
    {
        let (sender, receiver) = oneshot::channel();

        self.push(move || {
            let _ = sender.send(panic::catch_unwind(panic::AssertUnwindSafe(func)));
        })?;

        Ok(async move { receiver.await.expect("Dropped before executing") })
    }

    #[doc(alias = "g_thread_pool_set_max_threads")]
    pub fn set_max_threads(&self, max_threads: Option<u32>) -> Result<(), crate::Error> {
        let exclusive = unsafe { from_glib((*self.0.as_ptr()).exclusive) };
        let max_threads = checked_thread_limit(max_threads, exclusive)?;
        unsafe {
            let mut err = ptr::null_mut();
            let ret: bool = from_glib(ffi::g_thread_pool_set_max_threads(
                self.0.as_ptr(),
                max_threads,
                &mut err,
            ));
            if ret {
                Ok(())
            } else {
                Err(thread_pool_error(
                    err,
                    "GLib could not change the thread limit",
                ))
            }
        }
    }

    #[doc(alias = "g_thread_pool_get_max_threads")]
    #[doc(alias = "get_max_threads")]
    pub fn max_threads(&self) -> Option<u32> {
        unsafe {
            let max_threads = ffi::g_thread_pool_get_max_threads(self.0.as_ptr());
            if max_threads == -1 {
                None
            } else {
                Some(max_threads as u32)
            }
        }
    }

    #[doc(alias = "g_thread_pool_get_num_threads")]
    #[doc(alias = "get_num_threads")]
    pub fn num_threads(&self) -> u32 {
        unsafe { ffi::g_thread_pool_get_num_threads(self.0.as_ptr()) }
    }

    #[doc(alias = "g_thread_pool_unprocessed")]
    #[doc(alias = "get_unprocessed")]
    pub fn unprocessed(&self) -> u32 {
        unsafe { ffi::g_thread_pool_unprocessed(self.0.as_ptr()) }
    }

    /// # Panics
    ///
    /// Panics if a finite limit exceeds GLib's signed integer range.
    #[doc(alias = "g_thread_pool_set_max_unused_threads")]
    pub fn set_max_unused_threads(max_threads: Option<u32>) {
        let max_threads = checked_thread_limit(max_threads, false)
            .expect("Thread limit exceeds GLib's signed range");
        unsafe { ffi::g_thread_pool_set_max_unused_threads(max_threads) }
    }

    #[doc(alias = "g_thread_pool_get_max_unused_threads")]
    #[doc(alias = "get_max_unused_threads")]
    pub fn max_unused_threads() -> Option<u32> {
        unsafe {
            let max_unused_threads = ffi::g_thread_pool_get_max_unused_threads();
            if max_unused_threads == -1 {
                None
            } else {
                Some(max_unused_threads as u32)
            }
        }
    }

    #[doc(alias = "g_thread_pool_get_num_unused_threads")]
    #[doc(alias = "get_num_unused_threads")]
    pub fn num_unused_threads() -> u32 {
        unsafe { ffi::g_thread_pool_get_num_unused_threads() }
    }

    #[doc(alias = "g_thread_pool_stop_unused_threads")]
    pub fn stop_unused_threads() {
        unsafe {
            ffi::g_thread_pool_stop_unused_threads();
        }
    }

    #[doc(alias = "g_thread_pool_set_max_idle_time")]
    pub fn set_max_idle_time(max_idle_time: u32) {
        unsafe { ffi::g_thread_pool_set_max_idle_time(max_idle_time) }
    }

    #[doc(alias = "g_thread_pool_get_max_idle_time")]
    #[doc(alias = "get_max_idle_time")]
    pub fn max_idle_time() -> u32 {
        unsafe { ffi::g_thread_pool_get_max_idle_time() }
    }
}

impl Drop for ThreadPool {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::g_thread_pool_free(self.0.as_ptr(), ffi::GFALSE, ffi::GTRUE);
        }
    }
}

unsafe extern "C" fn spawn_func(func: ffi::gpointer, _data: ffi::gpointer) {
    let func: Box<Box<dyn FnOnce()>> = Box::from_raw(func as *mut _);
    func()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_thread_limit_conversion_accepts_valid_bounds_without_spawning() {
        for exclusive in [false, true] {
            assert_eq!(checked_thread_limit(Some(0), exclusive).unwrap(), 0);
            assert_eq!(
                checked_thread_limit(Some(i32::MAX as u32), exclusive).unwrap(),
                i32::MAX,
            );
        }
        assert_eq!(checked_thread_limit(None, false).unwrap(), -1);
        assert!(checked_thread_limit(None, true).is_err());
    }

    #[test]
    fn oversized_constructor_limits_are_rejected_before_c() {
        for limit in [i32::MAX as u32 + 1, u32::MAX] {
            for result in [
                ThreadPool::shared(Some(limit)),
                ThreadPool::exclusive(limit),
            ] {
                let error = result.unwrap_err();
                assert_eq!(error.domain(), unsafe {
                    from_glib(ffi::g_thread_error_quark())
                });
                assert_eq!(error.message(), "Thread limit exceeds GLib's signed range");
            }
        }
    }

    #[test]
    fn exclusive_unlimited_setter_is_rejected_without_state_change() {
        let pool = ThreadPool::exclusive(0).unwrap();
        assert!(pool.set_max_threads(None).is_err());
        assert_eq!(pool.max_threads(), Some(0));
        assert_eq!(pool.num_threads(), 0);
    }

    #[test]
    fn shared_zero_pool_accepts_unlimited_without_starting_workers() {
        let pool = ThreadPool::shared(Some(0)).unwrap();
        assert_eq!(pool.num_threads(), 0);
        pool.set_max_threads(None).unwrap();
        assert_eq!(pool.max_threads(), None);
        assert_eq!(pool.num_threads(), 0);
    }

    #[test]
    fn oversized_setter_limits_preserve_pool_state() {
        for pool in [
            ThreadPool::shared(Some(0)).unwrap(),
            ThreadPool::exclusive(0).unwrap(),
        ] {
            for limit in [i32::MAX as u32 + 1, u32::MAX] {
                assert!(pool.set_max_threads(Some(limit)).is_err());
                assert_eq!(pool.max_threads(), Some(0));
                assert_eq!(pool.num_threads(), 0);
            }
        }
    }

    #[test]
    fn invalid_unused_limit_panics_before_changing_global_setting() {
        let previous = ThreadPool::max_unused_threads();
        for limit in [i32::MAX as u32 + 1, u32::MAX] {
            assert!(
                panic::catch_unwind(|| ThreadPool::set_max_unused_threads(Some(limit))).is_err()
            );
            assert_eq!(ThreadPool::max_unused_threads(), previous);
        }
    }

    #[test]
    fn missing_constructor_error_has_valid_owned_fallback() {
        let error =
            unsafe { ThreadPool::from_created_pool(ptr::null_mut(), ptr::null_mut()).unwrap_err() };
        assert_eq!(error.domain(), unsafe {
            from_glib(ffi::g_thread_error_quark())
        });
        assert_eq!(error.message(), "GLib could not create a thread pool");
    }

    #[test]
    fn partial_constructor_failure_retires_empty_pool_and_preserves_error() {
        let pool = ThreadPool::shared(Some(0)).unwrap();
        let raw_pool = pool.0.as_ptr();
        assert_eq!(pool.unprocessed(), 0);
        std::mem::forget(pool);
        let error = unsafe {
            let error = ffi::g_error_new_literal(
                ffi::g_thread_error_quark(),
                ffi::G_THREAD_ERROR_AGAIN,
                "test partial construction failure".to_glib_none().0,
            );
            ThreadPool::from_created_pool(raw_pool, error).unwrap_err()
        };
        assert_eq!(error.message(), "test partial construction failure");
        assert_eq!(error.domain(), unsafe {
            from_glib(ffi::g_thread_error_quark())
        });
    }

    #[test]
    fn failed_worker_start_keeps_queued_callback_owned() {
        use std::{
            cell::Cell,
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
        };
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let capture = Dropped(drops.clone());
        let queued = Cell::new(ptr::null_mut());
        let pool = ThreadPool::exclusive(1).unwrap();
        let result = pool.push_with(
            move || {
                drop(capture);
                123
            },
            |_, data, error| {
                queued.set(data);
                unsafe {
                    *error = ffi::g_error_new_literal(
                        ffi::g_thread_error_quark(),
                        ffi::G_THREAD_ERROR_AGAIN,
                        "test worker start failure".to_glib_none().0,
                    );
                }
                false
            },
        );
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!queued.get().is_null());
        unsafe {
            spawn_func(queued.replace(ptr::null_mut()), ptr::null_mut());
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_push() {
        use std::sync::mpsc;

        let p = ThreadPool::exclusive(1).unwrap();
        let (sender, receiver) = mpsc::channel();

        let handle = p
            .push(move || {
                sender.send(true).unwrap();
                123
            })
            .unwrap();

        assert_eq!(handle.join().unwrap(), 123);
        assert_eq!(receiver.recv(), Ok(true));
    }

    #[test]
    fn test_push_future() {
        let c = crate::MainContext::new();
        let p = ThreadPool::shared(None).unwrap();

        let fut = p.push_future(|| true).unwrap();

        let res = c.block_on(fut);
        assert!(res.unwrap());
    }
}
