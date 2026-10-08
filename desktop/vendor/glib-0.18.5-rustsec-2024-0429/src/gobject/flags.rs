// Take a look at the license at the top of the repository in the LICENSE file.

use crate::translate::*;

bitflags::bitflags! {
    #[doc(alias = "GParamFlags")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ParamFlags: u32 {
        #[doc(alias = "G_PARAM_READABLE")]
        const READABLE = gobject_ffi::G_PARAM_READABLE as _;
        #[doc(alias = "G_PARAM_WRITABLE")]
        const WRITABLE = gobject_ffi::G_PARAM_WRITABLE as _;
        #[doc(alias = "G_PARAM_READWRITE")]
        const READWRITE = gobject_ffi::G_PARAM_READWRITE as _;
        #[doc(alias = "G_PARAM_CONSTRUCT")]
        const CONSTRUCT = gobject_ffi::G_PARAM_CONSTRUCT as _;
        #[doc(alias = "G_PARAM_CONSTRUCT_ONLY")]
        const CONSTRUCT_ONLY = gobject_ffi::G_PARAM_CONSTRUCT_ONLY as _;
        #[doc(alias = "G_PARAM_LAX_VALIDATION")]
        const LAX_VALIDATION = gobject_ffi::G_PARAM_LAX_VALIDATION as _;
        const USER_0 = 256;
        const USER_1 = 512;
        const USER_2 = 1024;
        const USER_3 = 2048;
        const USER_4 = 4096;
        const USER_5 = 8192;
        const USER_6 = 16384;
        const USER_7 = 32768;
        const USER_8 = 65536;
        #[doc(alias = "G_PARAM_EXPLICIT_NOTIFY")]
        const EXPLICIT_NOTIFY = gobject_ffi::G_PARAM_EXPLICIT_NOTIFY as _;
        #[doc(alias = "G_PARAM_DEPRECATED")]
        const DEPRECATED = gobject_ffi::G_PARAM_DEPRECATED as _;
    }
}

impl Default for ParamFlags {
    fn default() -> Self {
        ParamFlags::READWRITE
    }
}

#[doc(hidden)]
impl IntoGlib for ParamFlags {
    type GlibType = gobject_ffi::GParamFlags;

    #[inline]
    fn into_glib(self) -> gobject_ffi::GParamFlags {
        // These ownership flags are deliberately not exposed by the safe
        // wrapper. `from_bits_retain` must not restore borrowed C metadata.
        self.bits()
            & !(gobject_ffi::G_PARAM_STATIC_NAME
                | gobject_ffi::G_PARAM_STATIC_NICK
                | gobject_ffi::G_PARAM_STATIC_BLURB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::ParamSpecBuilderExt;

    #[test]
    fn retained_bits_cannot_make_parameter_metadata_borrowed() {
        let static_bits = gobject_ffi::G_PARAM_STATIC_NAME
            | gobject_ffi::G_PARAM_STATIC_NICK
            | gobject_ffi::G_PARAM_STATIC_BLURB;
        let ordinary_bits = ParamFlags::READWRITE.bits() | ParamFlags::USER_8.bits();
        let flags = ParamFlags::from_bits_retain(static_bits | ordinary_bits);
        assert_eq!(flags.into_glib(), ordinary_bits);
        let parameter = {
            let name = String::from("owned-metadata");
            let nick = String::from("owned nick");
            let blurb = String::from("owned description");
            crate::ParamSpecString::builder(&name)
                .nick(&nick)
                .blurb(&blurb)
                .flags(flags)
                .build()
        };
        assert_eq!(parameter.name(), "owned-metadata");
        assert_eq!(parameter.nick(), "owned nick");
        assert_eq!(parameter.blurb(), Some("owned description"));
    }
}

#[doc(hidden)]
impl FromGlib<gobject_ffi::GParamFlags> for ParamFlags {
    #[inline]
    unsafe fn from_glib(value: gobject_ffi::GParamFlags) -> Self {
        Self::from_bits_truncate(value)
    }
}
