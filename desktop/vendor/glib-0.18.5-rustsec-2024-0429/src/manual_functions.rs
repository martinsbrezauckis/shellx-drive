// Take a look at the license at the top of the repository in the LICENSE file.

#[cfg(not(windows))]
use std::boxed::Box as Box_;
#[cfg(not(windows))]
#[cfg(feature = "v2_58")]
use std::os::unix::io::AsRawFd;
#[cfg(not(windows))]
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::ptr;

// #[cfg(windows)]
// #[cfg(feature = "v2_58")]
// use std::os::windows::io::AsRawHandle;
use crate::{translate::*, GString};
#[cfg(not(windows))]
use crate::{Error, Pid, SpawnFlags};

#[cfg(feature = "v2_58")]
#[cfg(not(windows))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v2_58", not(windows)))))]
#[allow(clippy::too_many_arguments)]
#[doc(alias = "g_spawn_async_with_fds")]
pub fn spawn_async_with_fds<P: AsRef<std::path::Path>, T: AsRawFd, U: AsRawFd, V: AsRawFd>(
    working_directory: P,
    argv: &[&str],
    envp: &[&str],
    flags: SpawnFlags,
    child_setup: Option<Box_<dyn FnOnce() + 'static>>,
    stdin_fd: T,
    stdout_fd: U,
    stderr_fd: V,
) -> Result<Pid, Error> {
    if argv.is_empty() {
        return Err(unsafe {
            from_glib_full(ffi::g_error_new_literal(
                ffi::g_spawn_error_quark(),
                ffi::G_SPAWN_ERROR_FAILED,
                "process argument list is empty".to_glib_none().0,
            ))
        });
    }
    let child_setup_data: Box_<Option<Box_<dyn FnOnce() + 'static>>> = Box_::new(child_setup);
    unsafe extern "C" fn child_setup_func(user_data: ffi::gpointer) {
        let callback: Box_<Option<Box_<dyn FnOnce() + 'static>>> =
            Box_::from_raw(user_data as *mut _);
        let callback = (*callback).expect("cannot get closure...");
        callback()
    }
    let child_setup = if child_setup_data.is_some() {
        Some(child_setup_func as _)
    } else {
        None
    };
    let mut super_callback0: Box_<Option<Box_<dyn FnOnce() + 'static>>> = child_setup_data;
    unsafe {
        let mut child_pid = 0;
        let mut error = ptr::null_mut();
        let succeeded = ffi::g_spawn_async_with_fds(
            working_directory.as_ref().to_glib_none().0,
            argv.to_glib_none().0,
            envp.to_glib_none().0,
            flags.into_glib(),
            child_setup,
            &mut *super_callback0 as *mut _ as *mut _,
            &mut child_pid,
            stdin_fd.as_raw_fd(),
            stdout_fd.as_raw_fd(),
            stderr_fd.as_raw_fd(),
            &mut error,
        );
        if !error.is_null() {
            Err(from_glib_full(error))
        } else if succeeded == ffi::GFALSE {
            Err(from_glib_full(ffi::g_error_new_literal(
                ffi::g_spawn_error_quark(),
                ffi::G_SPAWN_ERROR_FAILED,
                "GLib rejected process arguments".to_glib_none().0,
            )))
        } else {
            Ok(from_glib(child_pid))
        }
    }
}

// #[cfg(feature = "v2_58")]
// #[cfg(windows)]
// pub fn spawn_async_with_fds<
//     P: AsRef<std::path::Path>,
//     T: AsRawHandle,
//     U: AsRawHandle,
//     V: AsRawHandle,
// >(
//     working_directory: P,
//     argv: &[&str],
//     envp: &[&str],
//     flags: SpawnFlags,
//     child_setup: Option<Box_<dyn FnOnce() + 'static>>,
//     stdin_fd: T,
//     stdout_fd: U,
//     stderr_fd: V,
// ) -> Result<Pid, Error> {
//     let child_setup_data: Box_<Option<Box_<dyn FnOnce() + 'static>>> = Box_::new(child_setup);
//     unsafe extern "C" fn child_setup_func<P: AsRef<std::path::Path>>(
//         user_data: ffi::gpointer,
//     ) {
//         let callback: Box_<Option<Box_<dyn FnOnce() + 'static>>> =
//             Box_::from_raw(user_data as *mut _);
//         let callback = (*callback).expect("cannot get closure...");
//         callback()
//     }
//     let child_setup = if child_setup_data.is_some() {
//         Some(child_setup_func::<P> as _)
//     } else {
//         None
//     };
//     let super_callback0: Box_<Option<Box_<dyn FnOnce() + 'static>>> = child_setup_data;
//     unsafe {
//         let mut child_pid = mem::MaybeUninit::uninit();
//         let mut error = ptr::null_mut();
//         let _ = ffi::g_spawn_async_with_fds(
//             working_directory.as_ref().to_glib_none().0,
//             argv.to_glib_none().0,
//             envp.to_glib_none().0,
//             flags.into_glib(),
//             child_setup,
//             Box_::into_raw(super_callback0) as *mut _,
//             child_pid.as_mut_ptr(),
//             stdin_fd.as_raw_handle() as usize as _,
//             stdout_fd.as_raw_handle() as usize as _,
//             stderr_fd.as_raw_handle() as usize as _,
//             &mut error,
//         );
//         let child_pid = from_glib(child_pid.assume_init());
//         if error.is_null() {
//             Ok(child_pid)
//         } else {
//             Err(from_glib_full(error))
//         }
//     }
// }

#[cfg(not(windows))]
#[cfg_attr(docsrs, doc(cfg(not(windows))))]
#[doc(alias = "g_spawn_async_with_pipes")]
pub fn spawn_async_with_pipes<
    P: AsRef<std::path::Path>,
    T: FromRawFd,
    U: FromRawFd,
    V: FromRawFd,
>(
    working_directory: P,
    argv: &[&std::path::Path],
    envp: &[&std::path::Path],
    flags: SpawnFlags,
    child_setup: Option<Box_<dyn FnOnce() + 'static>>,
) -> Result<(Pid, T, U, V), Error> {
    if argv.is_empty() {
        return Err(unsafe {
            from_glib_full(ffi::g_error_new_literal(
                ffi::g_spawn_error_quark(),
                ffi::G_SPAWN_ERROR_FAILED,
                "process argument list is empty".to_glib_none().0,
            ))
        });
    }
    let child_setup_data: Box_<Option<Box_<dyn FnOnce() + 'static>>> = Box_::new(child_setup);
    unsafe extern "C" fn child_setup_func(user_data: ffi::gpointer) {
        let callback: Box_<Option<Box_<dyn FnOnce() + 'static>>> =
            Box_::from_raw(user_data as *mut _);
        let callback = (*callback).expect("cannot get closure...");
        callback()
    }
    let child_setup = if child_setup_data.is_some() {
        Some(child_setup_func as _)
    } else {
        None
    };
    let mut super_callback0: Box_<Option<Box_<dyn FnOnce() + 'static>>> = child_setup_data;
    unsafe {
        let mut child_pid = 0;
        let mut standard_input = -1;
        let mut standard_output = -1;
        let mut standard_error = -1;
        let mut error = ptr::null_mut();
        let succeeded = ffi::g_spawn_async_with_pipes(
            working_directory.as_ref().to_glib_none().0,
            argv.to_glib_none().0,
            envp.to_glib_none().0,
            flags.into_glib(),
            child_setup,
            &mut *super_callback0 as *mut _ as *mut _,
            &mut child_pid,
            &mut standard_input,
            &mut standard_output,
            &mut standard_error,
            &mut error,
        );
        if !error.is_null() {
            Err(from_glib_full(error))
        } else if succeeded == ffi::GFALSE {
            Err(from_glib_full(ffi::g_error_new_literal(
                ffi::g_spawn_error_quark(),
                ffi::G_SPAWN_ERROR_FAILED,
                "GLib rejected process arguments".to_glib_none().0,
            )))
        } else {
            assert!(standard_input >= 0 && standard_output >= 0 && standard_error >= 0);
            #[cfg(not(windows))]
            {
                Ok((
                    from_glib(child_pid),
                    FromRawFd::from_raw_fd(standard_input),
                    FromRawFd::from_raw_fd(standard_output),
                    FromRawFd::from_raw_fd(standard_error),
                ))
            }
            // #[cfg(windows)]
            // {
            //     use std::os::windows::io::{FromRawHandle, RawHandle};
            //     Ok((
            //         child_pid,
            //         File::from_raw_handle(standard_input as usize as RawHandle),
            //         File::from_raw_handle(standard_output as usize as RawHandle),
            //         File::from_raw_handle(standard_error as usize as RawHandle),
            //     ))
            // }
        }
    }
}

// rustdoc-stripper-ignore-next
/// Obtain the character set for the current locale.
///
/// This returns whether the locale's encoding is UTF-8, and the current
/// charset if available. The returned name is owned independently of GLib's
/// thread-local cache and remains valid after the originating thread exits.
#[doc(alias = "g_get_charset")]
#[doc(alias = "get_charset")]
pub fn charset() -> (bool, Option<GString>) {
    unsafe {
        let mut out_charset = ptr::null();
        let is_utf8 = from_glib(ffi::g_get_charset(&mut out_charset));
        let charset = from_glib_none(out_charset);
        (is_utf8, charset)
    }
}

#[cfg(unix)]
#[doc(alias = "g_unix_open_pipe")]
pub fn unix_open_pipe(flags: i32) -> Result<(RawFd, RawFd), Error> {
    unsafe {
        let mut fds = [0, 2];
        let mut error = ptr::null_mut();
        let _ = ffi::g_unix_open_pipe(&mut fds, flags, &mut error);
        if error.is_null() {
            Ok((
                FromRawFd::from_raw_fd(fds[0]),
                FromRawFd::from_raw_fd(fds[1]),
            ))
        } else {
            Err(from_glib_full(error))
        }
    }
}

#[cfg(unix)]
#[doc(alias = "g_file_open_tmp")]
pub fn file_open_tmp(
    tmpl: Option<impl AsRef<std::path::Path>>,
) -> Result<(RawFd, std::path::PathBuf), crate::Error> {
    unsafe {
        let mut name_used = ptr::null_mut();
        let mut error = ptr::null_mut();
        let ret = ffi::g_file_open_tmp(
            tmpl.as_ref().map(|p| p.as_ref()).to_glib_none().0,
            &mut name_used,
            &mut error,
        );
        if error.is_null() {
            Ok((ret.into_raw_fd(), from_glib_full(name_used)))
        } else {
            Err(from_glib_full(error))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn charset_name_is_owned_after_origin_thread_exits() {
        let (_, name) = std::thread::spawn(super::charset).join().unwrap();
        if let Some(name) = name {
            assert!(!name.is_empty());
            assert!(!name.as_bytes().contains(&0));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn pipe_spawn_rejects_empty_and_missing_program_without_reading_outputs() {
        use std::{fs::File, path::Path};
        for arguments in [Vec::new(), vec![Path::new("/shellx-drive-no-such-program")]] {
            let result: Result<(crate::Pid, File, File, File), crate::Error> =
                super::spawn_async_with_pipes(
                    ".",
                    &arguments,
                    &[],
                    crate::SpawnFlags::empty(),
                    None,
                );
            assert!(result.is_err());
            assert!(crate::spawn_async(
                Some(Path::new(".")),
                &arguments,
                &[],
                crate::SpawnFlags::empty(),
                None
            )
            .is_err());
        }
    }

    #[test]
    fn gettext_offsets_stay_inside_the_current_utf8_string() {
        assert!(std::panic::catch_unwind(|| crate::dpgettext(None, "é", 1)).is_err());
        assert!(
            std::panic::catch_unwind(|| crate::dpgettext(None, "message", usize::MAX)).is_err()
        );
        assert_eq!(
            crate::dpgettext(
                Some("shellx-drive-no-such-test-domain"),
                "context\u{4}message",
                8
            )
            .as_str(),
            "message"
        );
        assert_eq!(
            crate::dpgettext(Some("shellx-drive-no-such-test-domain"), "message", 7).as_str(),
            ""
        );
    }

    #[test]
    fn destroyed_sources_cannot_produce_an_invalid_source_identifier() {
        let context = crate::MainContext::new();
        let source = crate::source::idle_source_new(None, crate::Priority::DEFAULT, || {
            crate::ControlFlow::Continue
        });
        assert!(source.attach(Some(&context)).as_raw() > 0);
        source.destroy();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || source.attach(Some(&context))
        ))
        .is_err());
    }

    #[cfg(all(not(windows), feature = "v2_58"))]
    #[test]
    fn fd_spawn_rejects_empty_and_missing_program_without_reading_outputs() {
        let null = std::fs::File::open("/dev/null").unwrap();
        for arguments in [Vec::new(), vec!["/shellx-drive-no-such-program"]] {
            let result = super::spawn_async_with_fds(
                ".",
                &arguments,
                &[],
                crate::SpawnFlags::empty(),
                None,
                null.try_clone().unwrap(),
                null.try_clone().unwrap(),
                null.try_clone().unwrap(),
            );
            assert!(result.is_err());
        }
    }
}

// rustdoc-stripper-ignore-next
/// Spawn a new infallible `Future` on the thread-default main context.
///
/// This can be called from any thread and will execute the future from the thread
/// where main context is running, e.g. via a `MainLoop`.
pub fn spawn_future<R: Send + 'static, F: std::future::Future<Output = R> + Send + 'static>(
    f: F,
) -> crate::JoinHandle<R> {
    let ctx = crate::MainContext::ref_thread_default();
    ctx.spawn(f)
}

// rustdoc-stripper-ignore-next
/// Spawn a new infallible `Future` on the thread-default main context.
///
/// The given `Future` does not have to be `Send`.
///
/// This can be called only from the thread where the main context is running, e.g.
/// from any other `Future` that is executed on this main context, or after calling
/// `with_thread_default` or `acquire` on the main context.
pub fn spawn_future_local<R: 'static, F: std::future::Future<Output = R> + 'static>(
    f: F,
) -> crate::JoinHandle<R> {
    let ctx = crate::MainContext::ref_thread_default();
    ctx.spawn_local(f)
}
