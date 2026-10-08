// Take a look at the license at the top of the repository in the LICENSE file.

use std::{
    collections::VecDeque,
    fmt, mem, ptr,
    sync::{mpsc, Arc, Condvar, Mutex},
};

use crate::{
    thread_guard::ThreadGuard, translate::*, ControlFlow, MainContext, Priority, Source, SourceId,
};

enum ChannelSourceState {
    NotAttached,
    Attached(*mut ffi::GSource),
    Destroyed,
}

unsafe impl Send for ChannelSourceState {}
unsafe impl Sync for ChannelSourceState {}

struct ChannelInner<T> {
    queue: VecDeque<T>,
    source: ChannelSourceState,
    num_senders: usize,
}

impl<T> ChannelInner<T> {
    fn receiver_disconnected(&self) -> bool {
        match self.source {
            ChannelSourceState::Destroyed => true,
            // Receiver exists but is already destroyed
            ChannelSourceState::Attached(source)
                if unsafe { ffi::g_source_is_destroyed(source) } != ffi::GFALSE =>
            {
                true
            }
            // Not attached yet so the Receiver still exists
            ChannelSourceState::NotAttached => false,
            // Receiver still running
            ChannelSourceState::Attached(_) => false,
        }
    }

    #[doc(alias = "g_source_set_ready_time")]
    fn set_ready_time(&mut self, ready_time: i64) {
        if let ChannelSourceState::Attached(source) = self.source {
            unsafe {
                ffi::g_source_set_ready_time(source, ready_time);
            }
        }
    }
}

struct ChannelBound {
    bound: usize,
    cond: Condvar,
}

struct Channel<T>(Arc<(Mutex<ChannelInner<T>>, Option<ChannelBound>)>);

impl<T> Clone for Channel<T> {
    fn clone(&self) -> Channel<T> {
        Channel(self.0.clone())
    }
}

impl<T> Channel<T> {
    fn new(bound: Option<usize>) -> Channel<T> {
        Channel(Arc::new((
            Mutex::new(ChannelInner {
                queue: VecDeque::new(),
                source: ChannelSourceState::NotAttached,
                num_senders: 0,
            }),
            bound.map(|bound| ChannelBound {
                bound,
                cond: Condvar::new(),
            }),
        )))
    }

    fn send(&self, t: T) -> Result<(), mpsc::SendError<T>> {
        let mut inner = (self.0).0.lock().unwrap();

        // If we have a bounded channel then we need to wait here until enough free space is
        // available or the receiver disappears
        //
        // A special case here is a bound of 0: the queue must be empty for accepting
        // new data and then we will again wait later for the data to be actually taken
        // out
        if let Some(ChannelBound { bound, ref cond }) = (self.0).1 {
            while inner.queue.len() >= bound
                && !inner.queue.is_empty()
                && !inner.receiver_disconnected()
            {
                inner = cond.wait(inner).unwrap();
            }
        }

        // Error out directly if the receiver is disconnected
        if inner.receiver_disconnected() {
            return Err(mpsc::SendError(t));
        }

        // Store the item on our queue
        inner.queue.push_back(t);

        // and then wake up the GSource
        inner.set_ready_time(0);

        // If we have a bound of 0 we need to wait until the receiver actually
        // handled the data
        if let Some(ChannelBound { bound: 0, ref cond }) = (self.0).1 {
            while !inner.queue.is_empty() && !inner.receiver_disconnected() {
                inner = cond.wait(inner).unwrap();
            }

            // If the receiver was destroyed in the meantime take out the item and report an error
            if inner.receiver_disconnected() {
                // If the item is not in the queue anymore then the receiver just handled it before
                // getting disconnected and all is good
                if let Some(t) = inner.queue.pop_front() {
                    return Err(mpsc::SendError(t));
                }
            }
        }

        Ok(())
    }

    fn try_send(&self, t: T) -> Result<(), mpsc::TrySendError<T>> {
        let mut inner = (self.0).0.lock().unwrap();

        let ChannelBound { bound, ref cond } = (self.0)
            .1
            .as_ref()
            .expect("called try_send() on an unbounded channel");

        // Check if the queue is full and handle the special case of a 0 bound
        if inner.queue.len() >= *bound && !inner.queue.is_empty() {
            return Err(mpsc::TrySendError::Full(t));
        }

        // Error out directly if the receiver is disconnected
        if inner.receiver_disconnected() {
            return Err(mpsc::TrySendError::Disconnected(t));
        }

        // Store the item on our queue
        inner.queue.push_back(t);

        // and then wake up the GSource
        inner.set_ready_time(0);

        // If we have a bound of 0 we need to wait until the receiver actually
        // handled the data
        if *bound == 0 {
            while !inner.queue.is_empty() && !inner.receiver_disconnected() {
                inner = cond.wait(inner).unwrap();
            }

            // If the receiver was destroyed in the meantime take out the item and report an error
            if inner.receiver_disconnected() {
                // If the item is not in the queue anymore then the receiver just handled it before
                // getting disconnected and all is good
                if let Some(t) = inner.queue.pop_front() {
                    return Err(mpsc::TrySendError::Disconnected(t));
                }
            }
        }

        Ok(())
    }

    // SAFETY: Must be called from the main context the channel was attached to.
    unsafe fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
        let mut inner = (self.0).0.lock().unwrap();

        // Pop item if we have any
        if let Some(item) = inner.queue.pop_front() {
            // Wake up a sender that is currently waiting, if any
            if let Some(ChannelBound { ref cond, .. }) = (self.0).1 {
                cond.notify_one();
            }
            return Ok(item);
        }

        // If there are no senders left we are disconnected or otherwise empty. That's the case if
        // the only remaining strong reference is the one of the receiver
        if inner.num_senders == 0 {
            Err(mpsc::TryRecvError::Disconnected)
        } else {
            Err(mpsc::TryRecvError::Empty)
        }
    }
}

#[repr(C)]
struct ChannelSource<T, F: FnMut(T) -> ControlFlow + 'static> {
    source: ffi::GSource,
    source_funcs: Box<ffi::GSourceFuncs>,
    channel: Channel<T>,
    channel_owner: ThreadGuard<Channel<T>>,
    callback: ThreadGuard<F>,
}

type ChannelSourceData<T, F> = mem::ManuallyDrop<(ThreadGuard<F>, ThreadGuard<Channel<T>>)>;

fn drop_channel_data_if_owner<T, F>(data: &mut ChannelSourceData<T, F>) -> bool {
    if !data.0.is_owner() {
        return false;
    }
    // Both guards were created on the attaching thread. Only that thread may
    // destroy the callback or the final channel reference and its queued values.
    unsafe { mem::ManuallyDrop::drop(data) };
    true
}

fn channel_cleanup_source<T: 'static, F: FnMut(T) -> ControlFlow + 'static>(
    mut data: ChannelSourceData<T, F>,
) -> Source {
    crate::source::idle_source_new(None, Priority::DEFAULT_IDLE, move || {
        drop_channel_data_if_owner(&mut data);
        ControlFlow::Break
    })
}

unsafe extern "C" fn dispatch<T, F: FnMut(T) -> ControlFlow + 'static>(
    source: *mut ffi::GSource,
    callback: ffi::GSourceFunc,
    _user_data: ffi::gpointer,
) -> ffi::gboolean {
    let source = &mut *(source as *mut ChannelSource<T, F>);
    debug_assert!(callback.is_none());

    // Set ready-time to -1 so that we won't get called again before a new item is added
    // to the channel queue.
    ffi::g_source_set_ready_time(&mut source.source, -1);

    // Get a reference to the callback. This will panic if we're called from a different
    // thread than where the source was attached to the main context.
    let callback = source.callback.get_mut();

    // Now iterate over all items that we currently have in the channel until it is
    // empty again. If all senders are disconnected at some point we remove the GSource
    // from the main context it was attached to as it will never ever be called again.
    loop {
        match source.channel.try_recv() {
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => return ffi::G_SOURCE_REMOVE,
            Ok(item) => {
                if callback(item).is_break() {
                    return ffi::G_SOURCE_REMOVE;
                }
            }
        }
    }

    ffi::G_SOURCE_CONTINUE
}

#[cfg(feature = "v2_64")]
unsafe extern "C" fn dispose<T, F: FnMut(T) -> ControlFlow + 'static>(source: *mut ffi::GSource) {
    let source = &mut *(source as *mut ChannelSource<T, F>);

    // Set the source inside the channel to None so that all senders know that there
    // is no receiver left and wake up the condition variable if any
    let mut inner = (source.channel.0).0.lock().unwrap();
    inner.source = ChannelSourceState::Destroyed;
    if let Some(ChannelBound { ref cond, .. }) = (source.channel.0).1 {
        cond.notify_all();
    }
}

unsafe extern "C" fn finalize<T: 'static, F: FnMut(T) -> ControlFlow + 'static>(
    source: *mut ffi::GSource,
) {
    let source = &mut *(source as *mut ChannelSource<T, F>);

    // Drop all memory we own by taking it out of the Options

    #[cfg(not(feature = "v2_64"))]
    {
        // FIXME: This is the same as would otherwise be done in the dispose() function but
        // unfortunately it doesn't exist in older version of GLib. Doing it only here can
        // cause a channel sender to get a reference to the source with reference count 0
        // if it happens just before the mutex is taken below.
        //
        // This is exactly the pattern why g_source_set_dispose_function() was added.
        //
        // Set the source inside the channel to None so that all senders know that there
        // is no receiver left and wake up the condition variable if any
        let mut inner = (source.channel.0).0.lock().unwrap();
        inner.source = ChannelSourceState::Destroyed;
        if let Some(ChannelBound { ref cond, .. }) = (source.channel.0).1 {
            cond.notify_all();
        }
    }
    // Take both owner guards before dropping the ordinary channel reference.
    // Its clone in data prevents queued non-Send values from being the last
    // Arc-owned values destroyed by a foreign finalizer.
    let mut data = mem::ManuallyDrop::new((
        ptr::read(&source.callback),
        ptr::read(&source.channel_owner),
    ));
    ptr::drop_in_place(&mut source.channel);
    ptr::drop_in_place(&mut source.source_funcs);

    if !drop_channel_data_if_owner(&mut data) {
        let context =
            ffi::g_source_get_context(source as *mut ChannelSource<T, F> as *mut ffi::GSource);
        if !context.is_null() {
            let context = MainContext::from_glib_none(context);
            // Unlike invoke(), attachment never executes cleanup immediately on
            // a foreign thread when this context is temporarily unowned.
            channel_cleanup_source(data).attach(Some(&context));
        }
        // If the context is gone, cleanup is cancelled, or another thread
        // dispatches it, ManuallyDrop deliberately retains both guards. Neither
        // queued values nor the callback may be destroyed on the wrong thread.
    }
}

// rustdoc-stripper-ignore-next
/// A `Sender` that can be used to send items to the corresponding main context receiver.
///
/// This `Sender` behaves the same as `std::sync::mpsc::Sender`.
///
/// See [`MainContext::channel()`] for how to create such a `Sender`.
///
/// [`MainContext::channel()`]: struct.MainContext.html#method.channel
pub struct Sender<T>(Channel<T>);

// It's safe to send the Sender to other threads for attaching it as
// long as the items to be sent can also be sent between threads.
unsafe impl<T: Send> Send for Sender<T> {}

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Sender").finish()
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Sender<T> {
        Self::new(&self.0)
    }
}

impl<T> Sender<T> {
    fn new(channel: &Channel<T>) -> Self {
        let mut inner = (channel.0).0.lock().unwrap();
        inner.num_senders += 1;
        Self(channel.clone())
    }

    // rustdoc-stripper-ignore-next
    /// Sends a value to the channel.
    pub fn send(&self, t: T) -> Result<(), mpsc::SendError<T>> {
        self.0.send(t)
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // Decrease the number of senders and wake up the channel if this
        // was the last sender that was dropped.
        let mut inner = ((self.0).0).0.lock().unwrap();
        inner.num_senders -= 1;
        if inner.num_senders == 0 {
            inner.set_ready_time(0);
        }
    }
}

// rustdoc-stripper-ignore-next
/// A `SyncSender` that can be used to send items to the corresponding main context receiver.
///
/// This `SyncSender` behaves the same as `std::sync::mpsc::SyncSender`.
///
/// See [`MainContext::sync_channel()`] for how to create such a `SyncSender`.
///
/// [`MainContext::sync_channel()`]: struct.MainContext.html#method.sync_channel
pub struct SyncSender<T>(Channel<T>);

// It's safe to send the SyncSender to other threads for attaching it as
// long as the items to be sent can also be sent between threads.
unsafe impl<T: Send> Send for SyncSender<T> {}

impl<T> fmt::Debug for SyncSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SyncSender").finish()
    }
}

impl<T> Clone for SyncSender<T> {
    fn clone(&self) -> SyncSender<T> {
        Self::new(&self.0)
    }
}

impl<T> SyncSender<T> {
    fn new(channel: &Channel<T>) -> Self {
        let mut inner = (channel.0).0.lock().unwrap();
        inner.num_senders += 1;
        Self(channel.clone())
    }

    // rustdoc-stripper-ignore-next
    /// Sends a value to the channel and blocks if the channel is full.
    pub fn send(&self, t: T) -> Result<(), mpsc::SendError<T>> {
        self.0.send(t)
    }

    // rustdoc-stripper-ignore-next
    /// Sends a value to the channel.
    pub fn try_send(&self, t: T) -> Result<(), mpsc::TrySendError<T>> {
        self.0.try_send(t)
    }
}

impl<T> Drop for SyncSender<T> {
    fn drop(&mut self) {
        // Decrease the number of senders and wake up the channel if this
        // was the last sender that was dropped.
        let mut inner = ((self.0).0).0.lock().unwrap();
        inner.num_senders -= 1;
        if inner.num_senders == 0 {
            inner.set_ready_time(0);
        }
    }
}

// rustdoc-stripper-ignore-next
/// A `Receiver` that can be attached to a main context to receive items from its corresponding
/// `Sender` or `SyncSender`.
///
/// See [`MainContext::channel()`] or [`MainContext::sync_channel()`] for how to create
/// such a `Receiver`.
///
/// [`MainContext::channel()`]: struct.MainContext.html#method.channel
/// [`MainContext::sync_channel()`]: struct.MainContext.html#method.sync_channel
pub struct Receiver<T>(Option<Channel<T>>, Priority);

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Receiver").finish()
    }
}

// It's safe to send the Receiver to other threads for attaching it as
// long as the items to be sent can also be sent between threads.
unsafe impl<T: Send> Send for Receiver<T> {}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        // If the receiver was never attached to a main context we need to let all the senders know
        if let Some(channel) = self.0.take() {
            let mut inner = (channel.0).0.lock().unwrap();
            inner.source = ChannelSourceState::Destroyed;
            if let Some(ChannelBound { ref cond, .. }) = (channel.0).1 {
                cond.notify_all();
            }
        }
    }
}

impl<T> Receiver<T> {
    // rustdoc-stripper-ignore-next
    /// Attaches the receiver to the given `context` and calls `func` whenever an item is
    /// available on the channel.
    ///
    /// Passing `None` for the context will attach it to the thread default main context.
    /// Queued values must be owned independently of the caller. Non-Send values
    /// and local callback captures are destroyed only on the attaching thread.
    /// If a source is finalized elsewhere, cleanup is deferred to that thread
    /// through the original context. When the context is unavailable, cleanup
    /// is cancelled, or another thread dispatches it, the payload is retained
    /// rather than running thread-bound destructors on the wrong thread.
    ///
    /// ```
    /// use std::rc::Rc;
    /// let context = glib::MainContext::new();
    /// let _owner = context.acquire().unwrap();
    /// let (sender, receiver) = glib::MainContext::channel::<Rc<()>>(glib::Priority::DEFAULT);
    /// sender.send(Rc::new(())).unwrap();
    /// let id = receiver.attach(Some(&context), |_| glib::ControlFlow::Break);
    /// context.find_source_by_id(&id).unwrap().destroy();
    /// ```
    ///
    /// ```compile_fail
    /// fn dangling_value() -> glib::SourceId {
    ///     let text = String::from("local");
    ///     let (sender, receiver) = glib::MainContext::channel(glib::Priority::DEFAULT);
    ///     sender.send(text.as_str()).unwrap();
    ///     drop(sender);
    ///     receiver.attach(None, |_| glib::ControlFlow::Continue)
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function panics if called from a thread that is not the owner of the provided
    /// `context`, or, if `None` is provided, of the thread default main context.
    pub fn attach<F: FnMut(T) -> ControlFlow + 'static>(
        mut self,
        context: Option<&MainContext>,
        func: F,
    ) -> SourceId
    where
        T: 'static,
    {
        unsafe {
            let channel = self.0.take().expect("Receiver without channel");

            let source_funcs = Box::new(ffi::GSourceFuncs {
                check: None,
                prepare: None,
                dispatch: Some(dispatch::<T, F>),
                finalize: Some(finalize::<T, F>),
                closure_callback: None,
                closure_marshal: None,
            });

            let source = ffi::g_source_new(
                mut_override(&*source_funcs),
                mem::size_of::<ChannelSource<T, F>>() as u32,
            ) as *mut ChannelSource<T, F>;

            #[cfg(feature = "v2_64")]
            {
                ffi::g_source_set_dispose_function(
                    source as *mut ffi::GSource,
                    Some(dispose::<T, F>),
                );
            }

            // Set up the GSource
            {
                let source = &mut *source;
                let mut inner = (channel.0).0.lock().unwrap();

                ffi::g_source_set_priority(mut_override(&source.source), self.1.into_glib());

                // We're immediately ready if the queue is not empty or if no sender is left at this point
                ffi::g_source_set_ready_time(
                    mut_override(&source.source),
                    if !inner.queue.is_empty() || inner.num_senders == 0 {
                        0
                    } else {
                        -1
                    },
                );
                inner.source = ChannelSourceState::Attached(&mut source.source);
            }

            // Store all our data inside our part of the GSource
            {
                let source = &mut *source;
                ptr::write(
                    ptr::addr_of_mut!(source.channel_owner),
                    ThreadGuard::new(channel.clone()),
                );
                ptr::write(ptr::addr_of_mut!(source.channel), channel);
                ptr::write(ptr::addr_of_mut!(source.callback), ThreadGuard::new(func));
                ptr::write(ptr::addr_of_mut!(source.source_funcs), source_funcs);
            }

            let source = Source::from_glib_full(mut_override(&(*source).source));
            let context = match context {
                Some(context) => context.clone(),
                None => MainContext::ref_thread_default(),
            };

            let _acquire = context
                .acquire()
                .expect("main context already acquired by another thread");
            source.attach(Some(&context))
        }
    }
}

impl MainContext {
    // rustdoc-stripper-ignore-next
    /// Creates a channel for a main context.
    ///
    /// The `Receiver` has to be attached to a main context at a later time, together with a
    /// closure that will be called for every item sent to a `Sender`.
    ///
    /// The `Sender` can be cloned and both the `Sender` and `Receiver` can be sent to different
    /// threads as long as the item type implements the `Send` trait.
    ///
    /// When the last `Sender` is dropped the channel is removed from the main context. If the
    /// `Receiver` is dropped and not attached to a main context all sending to the `Sender`
    /// will fail.
    ///
    /// The returned `Sender` behaves the same as `std::sync::mpsc::Sender`.
    #[deprecated = "Use an async channel, from async-channel for example, on the main context using spawn_future_local() instead"]
    pub fn channel<T>(priority: Priority) -> (Sender<T>, Receiver<T>) {
        let channel = Channel::new(None);
        let receiver = Receiver(Some(channel.clone()), priority);
        let sender = Sender::new(&channel);

        (sender, receiver)
    }

    // rustdoc-stripper-ignore-next
    /// Creates a synchronous channel for a main context with a given bound on the capacity of the
    /// channel.
    ///
    /// The `Receiver` has to be attached to a main context at a later time, together with a
    /// closure that will be called for every item sent to a `SyncSender`.
    ///
    /// The `SyncSender` can be cloned and both the `SyncSender` and `Receiver` can be sent to different
    /// threads as long as the item type implements the `Send` trait.
    ///
    /// When the last `SyncSender` is dropped the channel is removed from the main context. If the
    /// `Receiver` is dropped and not attached to a main context all sending to the `SyncSender`
    /// will fail.
    ///
    /// The returned `SyncSender` behaves the same as `std::sync::mpsc::SyncSender`.
    #[deprecated = "Use an async channel, from async-channel for example, on the main context using spawn_future_local() instead"]
    pub fn sync_channel<T>(priority: Priority, bound: usize) -> (SyncSender<T>, Receiver<T>) {
        let channel = Channel::new(Some(bound));
        let receiver = Receiver(Some(channel.clone()), priority);
        let sender = SyncSender::new(&channel);

        (sender, receiver)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use std::{
        cell::RefCell,
        rc::Rc,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        thread, time,
    };

    use super::*;
    use crate::MainLoop;

    #[derive(Debug)]
    struct LocalDropProbe {
        drops: Arc<AtomicUsize>,
        owner: thread::ThreadId,
        _local: std::marker::PhantomData<Rc<()>>,
    }

    impl LocalDropProbe {
        fn new(drops: &Arc<AtomicUsize>) -> Self {
            Self {
                drops: drops.clone(),
                owner: thread::current().id(),
                _local: std::marker::PhantomData,
            }
        }
    }

    impl Drop for LocalDropProbe {
        fn drop(&mut self) {
            assert_eq!(self.owner, thread::current().id());
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn local_cleanup_data(
        drops: &Arc<AtomicUsize>,
    ) -> ChannelSourceData<LocalDropProbe, impl FnMut(LocalDropProbe) -> ControlFlow> {
        let channel = Channel::new(None);
        (channel.0)
            .0
            .lock()
            .unwrap()
            .queue
            .push_back(LocalDropProbe::new(drops));
        let callback_probe = LocalDropProbe::new(drops);
        let callback = move |_| {
            let _probe = &callback_probe;
            ControlFlow::Continue
        };
        let data = mem::ManuallyDrop::new((
            ThreadGuard::new(callback),
            ThreadGuard::new(channel.clone()),
        ));
        drop(channel);
        data
    }

    #[test]
    fn non_send_channel_source_drops_queued_values_and_callback_on_owner() {
        let context = MainContext::new();
        let _owner = context.acquire().unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = MainContext::channel(Priority::DEFAULT);
        sender.send(LocalDropProbe::new(&drops)).unwrap();
        let callback_probe = LocalDropProbe::new(&drops);
        let id = receiver.attach(Some(&context), move |_| {
            let _probe = &callback_probe;
            ControlFlow::Continue
        });
        drop(sender);
        let source = context.find_source_by_id(&id).unwrap();
        source.destroy();
        drop(source);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn foreign_channel_cleanup_is_deferred_until_owner_context_iteration() {
        let context = MainContext::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let data = local_cleanup_data(&drops);
        let foreign_context = context.clone();
        let source = thread::spawn(move || {
            let source = channel_cleanup_source(data);
            source.attach(Some(&foreign_context));
            source
        })
        .join()
        .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let _owner = context.acquire().unwrap();
        assert!(context.iteration(false));
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        drop(source);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn foreign_channel_cleanup_check_preserves_payload_for_owner() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut data = thread::spawn({
            let data = local_cleanup_data(&drops);
            move || {
                let mut data = data;
                assert!(!drop_channel_data_if_owner(&mut data));
                data
            }
        })
        .join()
        .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(drop_channel_data_if_owner(&mut data));
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancelled_foreign_channel_cleanup_retains_thread_bound_payload() {
        let context = MainContext::new();
        let _owner = context.acquire().unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let data = local_cleanup_data(&drops);
        let foreign_context = context.clone();
        thread::spawn(move || {
            let source = channel_cleanup_source(data);
            source.attach(Some(&foreign_context));
            source.destroy();
            drop(source);
        })
        .join()
        .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!context.pending());
    }

    #[test]
    fn test_channel() {
        let c = MainContext::new();
        let l = MainLoop::new(Some(&c), false);

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::channel(Priority::default());

        let sum = Rc::new(RefCell::new(0));
        let sum_clone = sum.clone();
        let l_clone = l.clone();
        receiver.attach(Some(&c), move |item| {
            *sum_clone.borrow_mut() += item;
            if *sum_clone.borrow() == 6 {
                l_clone.quit();
                ControlFlow::Break
            } else {
                ControlFlow::Continue
            }
        });

        sender.send(1).unwrap();
        sender.send(2).unwrap();
        sender.send(3).unwrap();

        l.run();

        assert_eq!(*sum.borrow(), 6);
    }

    #[test]
    fn test_drop_sender() {
        let c = MainContext::new();
        let l = MainLoop::new(Some(&c), false);

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::channel::<i32>(Priority::default());

        struct Helper(MainLoop);
        impl Drop for Helper {
            fn drop(&mut self) {
                self.0.quit();
            }
        }

        let helper = Helper(l.clone());
        receiver.attach(Some(&c), move |_| {
            let _helper = &helper;
            ControlFlow::Continue
        });

        drop(sender);

        l.run();
    }

    #[test]
    fn test_drop_receiver() {
        let (sender, receiver) = MainContext::channel::<i32>(Priority::default());

        drop(receiver);
        assert_eq!(sender.send(1), Err(mpsc::SendError(1)));
    }

    #[test]
    fn test_remove_receiver() {
        let c = MainContext::new();

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::channel::<i32>(Priority::default());

        let source_id = receiver.attach(Some(&c), move |_| ControlFlow::Continue);

        let source = c.find_source_by_id(&source_id).unwrap();
        source.destroy();

        assert_eq!(sender.send(1), Err(mpsc::SendError(1)));
    }

    #[test]
    fn test_remove_receiver_and_drop_source() {
        let c = MainContext::new();

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::channel::<i32>(Priority::default());

        struct Helper(Arc<AtomicBool>);
        impl Drop for Helper {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let helper = Helper(dropped.clone());
        let source_id = receiver.attach(Some(&c), move |_| {
            let _helper = &helper;
            ControlFlow::Continue
        });

        let source = c.find_source_by_id(&source_id).unwrap();
        source.destroy();

        // This should drop the closure
        drop(source);

        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(sender.send(1), Err(mpsc::SendError(1)));
    }

    #[test]
    fn test_sync_channel() {
        let c = MainContext::new();
        let l = MainLoop::new(Some(&c), false);

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::sync_channel(Priority::default(), 2);

        let sum = Rc::new(RefCell::new(0));
        let sum_clone = sum.clone();
        let l_clone = l.clone();
        receiver.attach(Some(&c), move |item| {
            *sum_clone.borrow_mut() += item;
            if *sum_clone.borrow() == 6 {
                l_clone.quit();
                ControlFlow::Break
            } else {
                ControlFlow::Continue
            }
        });

        let (wait_sender, wait_receiver) = mpsc::channel();

        let thread = thread::spawn(move || {
            // The first two must succeed
            sender.try_send(1).unwrap();
            sender.try_send(2).unwrap();

            // This fill up the channel
            assert!(sender.try_send(3).is_err());
            wait_sender.send(()).unwrap();

            // This will block
            sender.send(3).unwrap();
        });

        // Wait until the channel is full, and then another
        // 50ms to make sure the sender is blocked now and
        // can wake up properly once an item was consumed
        assert!(wait_receiver.recv().is_ok());
        thread::sleep(time::Duration::from_millis(50));
        l.run();

        thread.join().unwrap();

        assert_eq!(*sum.borrow(), 6);
    }

    #[test]
    fn test_sync_channel_drop_wakeup() {
        let c = MainContext::new();
        let l = MainLoop::new(Some(&c), false);

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::sync_channel(Priority::default(), 3);

        let sum = Rc::new(RefCell::new(0));
        let sum_clone = sum.clone();
        let l_clone = l.clone();
        receiver.attach(Some(&c), move |item| {
            *sum_clone.borrow_mut() += item;
            if *sum_clone.borrow() == 6 {
                l_clone.quit();
                ControlFlow::Break
            } else {
                ControlFlow::Continue
            }
        });

        let (wait_sender, wait_receiver) = mpsc::channel();

        let thread = thread::spawn(move || {
            // The first three must succeed
            sender.try_send(1).unwrap();
            sender.try_send(2).unwrap();
            sender.try_send(3).unwrap();

            wait_sender.send(()).unwrap();
            for i in 4.. {
                // This will block at some point until the
                // receiver is removed from the main context
                if sender.send(i).is_err() {
                    break;
                }
            }
        });

        // Wait until the channel is full, and then another
        // 50ms to make sure the sender is blocked now and
        // can wake up properly once an item was consumed
        assert!(wait_receiver.recv().is_ok());
        thread::sleep(time::Duration::from_millis(50));
        l.run();

        thread.join().unwrap();

        assert_eq!(*sum.borrow(), 6);
    }

    #[test]
    fn test_sync_channel_drop_receiver_wakeup() {
        let c = MainContext::new();

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::sync_channel(Priority::default(), 2);

        let (wait_sender, wait_receiver) = mpsc::channel();

        let thread = thread::spawn(move || {
            // The first two must succeed
            sender.try_send(1).unwrap();
            sender.try_send(2).unwrap();
            wait_sender.send(()).unwrap();

            // This will block and then error out because the receiver is destroyed
            assert!(sender.send(3).is_err());
        });

        // Wait until the channel is full, and then another
        // 50ms to make sure the sender is blocked now and
        // can wake up properly once an item was consumed
        assert!(wait_receiver.recv().is_ok());
        thread::sleep(time::Duration::from_millis(50));
        drop(receiver);
        thread.join().unwrap();
    }

    #[test]
    fn test_sync_channel_rendezvous() {
        let c = MainContext::new();
        let l = MainLoop::new(Some(&c), false);

        let _guard = c.acquire().unwrap();

        let (sender, receiver) = MainContext::sync_channel(Priority::default(), 0);

        let (wait_sender, wait_receiver) = mpsc::channel();

        let thread = thread::spawn(move || {
            wait_sender.send(()).unwrap();
            sender.send(1).unwrap();
            wait_sender.send(()).unwrap();
            sender.send(2).unwrap();
            wait_sender.send(()).unwrap();
            sender.send(3).unwrap();
            wait_sender.send(()).unwrap();
        });

        // Wait until the thread is started, then wait another 50ms and
        // during that time it must not have proceeded yet to send the
        // second item because we did not yet receive the first item.
        assert!(wait_receiver.recv().is_ok());
        assert_eq!(
            wait_receiver.recv_timeout(time::Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );

        let sum = Rc::new(RefCell::new(0));
        let sum_clone = sum.clone();
        let l_clone = l.clone();
        receiver.attach(Some(&c), move |item| {
            // We consumed one item so there should be one item on
            // the other receiver now.
            assert!(wait_receiver.recv().is_ok());
            *sum_clone.borrow_mut() += item;
            if *sum_clone.borrow() == 6 {
                // But as we didn't consume the next one yet, there must be no
                // other item available yet
                assert_eq!(
                    wait_receiver.recv_timeout(time::Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Disconnected)
                );
                l_clone.quit();
                ControlFlow::Break
            } else {
                // But as we didn't consume the next one yet, there must be no
                // other item available yet
                assert_eq!(
                    wait_receiver.recv_timeout(time::Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                );
                ControlFlow::Continue
            }
        });
        l.run();

        thread.join().unwrap();

        assert_eq!(*sum.borrow(), 6);
    }
}
