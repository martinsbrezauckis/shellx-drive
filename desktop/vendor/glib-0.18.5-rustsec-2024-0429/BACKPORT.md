# RUSTSEC-2024-0429 backport provenance

This directory retains the complete crates.io `glib` 0.18.5 source archive for
the desktop workspace's GTK3-compatible dependency graph.

- Base archive: `glib-0.18.5.crate` from the existing Cargo registry cache.
- Verified SHA-256: `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`.
- Base source VCS revision: `42b9caf98e03ded086362d9653ca58fe94dc8658`, retained in
  `.cargo_vcs_info.json`.
- Upstream correction: <https://github.com/gtk-rs/gtk-rs-core/pull/1343>,
  commit `b5a4071`.

The existing correction in `src/variant_iter.rs` is retained:
`VariantStrIter::impl_get` declares the C out-pointer as
mutable and passes `&mut p` to `g_variant_get_child`. This is the complete
upstream correction for RUSTSEC-2024-0429.

The retained source also corrects six independent safe-API invariants:

- `vendor-glib-boxed-inline-full-slice`: the contiguous full/container slice
  conversion now allocates every element, with checked size multiplication.
  Empty slices retain the prior one-element allocation behavior.
- `vendor-glib-strv-clear-stale-pointers`: clearing an allocated vector writes
  its null sentinel before drop or reuse. The first reserve also initializes
  that sentinel, so an empty reserved vector can be dropped safely.
- `vendor-glib-foreign-gstring-byte-length`: foreign lengths exclude the null
  terminator. Byte conversion now uses `len`, or `len + 1` when the terminator
  is required, including empty builder strings and safe CString conversion.
- `vendor-glib-logfield-value-lifetime`: the borrowed value now shares the
  field's lifetime with its key, so safe code cannot retain a dangling value.
- `vendor-glib-list-retain-pointer-lifecycle`: List and SList predicates borrow
  the node's pointer slot, and each deletion uses the current live head.
- `vendor-glib-list-container-copy`: borrowed container conversions copy linked
  nodes through GLib while retaining borrowed element ownership. Empty lists
  produce null containers.

The slice element allocation and clear sentinel follow the current upstream
implementations inspected on 2026-10-04:
<https://github.com/gtk-rs/gtk-rs-core/blob/main/glib/src/boxed_inline.rs> and
<https://github.com/gtk-rs/gtk-rs-core/blob/main/glib/src/collections/strv.rs>.
Checked multiplication is an additional local guard. The reserve initialization
also matches the locally retained upstream glib 0.21.5 source. The GString and
LogField corrections are local patches; no upstream correction or advisory ID
is claimed for them.

Regression tests remain inside the six existing source files. They cover
multi-element slice round trips, clear/drop/reuse and empty reserve/drop,
foreign byte content and CString termination, and live LogField values. A
compile-fail LogField doctest rejects a value whose lifetime is too short.
Collection tests also read predicate elements, remove consecutive heads and
all elements, and check empty and nonempty copied-container ownership.
These Rust tests and the doctest require native qualification; inventory
verification alone does not prove they ran.

Nine further local safety classes are corrected in the retained source:

- `ThreadGuard` keeps its value in `ManuallyDrop`, so rejecting a foreign-thread
  drop cannot destroy a thread-bound value while unwinding.
- Empty `Slice` and `PtrSlice` conversions return a fresh empty destination
  before taking raw ownership, dropping the empty source exactly once.
- Unicode conversion wrappers take one `AsRef` view for both the C pointer and
  its length, preventing caller-defined views from disagreeing between calls.
- URI segment unescaping treats the optional end string as a source suffix.
  Its C end pointer is derived from the source allocation; a non-suffix returns
  `None` instead of passing unrelated allocation endpoints to GLib.
- `MainContext` join handles implement `Send` only for `Send` results. Local
  tasks can still return thread-bound values without moving their handles
  across threads.
- `StrV` extension writes a null terminator after each completed append, so a
  later caller-defined string view panic leaves the partial vector droppable.
- Retained Variant byte and fixed-array owners require `Send + 'static`.
  Fixed-array conversion preserves the array type rather than its element type.
- Parameter builders recheck canonical, nonempty names, including builders
  created through public `Default`. Numeric constructors admit only inclusive
  bounds containing the default, rejecting inverted ranges and NaN values
  before entering GLib.
- Serialized Variant constructors reject indefinite types before C construction
  or owner transfer. Shared wrappers enforce their non-null invariant in
  release builds before reference acquisition or `NonNull` construction.

These are local corrections; no upstream patch, advisory ID or deployed Drive
attack path is claimed for them. Their tests cover ownership and drop behavior,
stable conversion views, URI suffixes, local and transferable task results,
partial extension unwinding, retained byte ownership, names, numeric boundaries
and definite types. Compile-fail cases cover result and byte-owner bounds.
Source and checksum review remain separate from actual native test execution.

Native qualification with Rust 1.99.0 also exposed an upstream test fixture
defect in `test_into_strv`: its callback slice excludes the allocated null
terminator, so unchecked slice indexing at the slice length was invalid. The
fixture now reads that backed C terminator through the raw pointer while
retaining its length and content assertions. Production conversion code is
unchanged by this fixture correction.

Further local corrections protect the remaining safe wrapper boundaries:

- Boxed `Vec<GString>` values copy their strings into GLib-owned storage before
  releasing the Rust vector. Parameter flags remove the hidden static-metadata
  bits even when a caller retains otherwise unknown bits.
- Spawn wrappers initialize their outputs and check the C status and error
  before reading them. The parent retains the child-setup closure until the
  synchronous spawn call returns. Unix and Windows use their actual `GPid`
  representation. Charset lookup returns an owned string copied before the
  thread-local C storage can expire.
- List and SList removals unlink and advance their live head before an element
  destructor runs. Slice and PtrSlice clear/truncate commit their remaining
  ownership first; pointer slices also write their terminator. Clone and StrV
  constructors commit each completed element, keeping partial construction
  droppable if a user conversion, clone or destructor panics.
- Nonoptional GStr/GString conversions reject null pointers in release builds.
  An absent KeyFile comment becomes an empty owned string while C errors remain
  errors. The existing TimeZone wrapper is protected by the shared non-null
  conversion guard.
- Nonoptional boxed and object conversions also enforce their null invariant
  in release builds, before copying, taking references or constructing Rust
  references. Optional conversions continue to represent null as `None`.
- Path and OS-string Variant extraction checks the bytestring type. Fixed bool
  arrays validate each serialized byte as zero or one before creating Rust bool
  references.
- Binding transforms accept owned typed values with invocation-scoped lifetime
  bounds. Callers needing borrowed values use the existing `_with_values`
  methods. The retained tests preserve owned, scoped and failed-transform cases.
  The builder checks canonical same-object properties, property permissions and
  boolean inversion before transferring callback storage. Custom transforms
  retain GLib's behavior of overriding boolean inversion. An unexpected null
  result releases the unclaimed transform storage before panicking.
- ThreadPool push preserves the callback when GLib reports a thread-start
  failure but still queues its data. Thread limits must fit GLib's signed
  representation, and exclusive pools reject the unlimited sentinel. Nullable
  constructor/setter errors become owned fallback errors; partial constructor
  results are retired before returning an error. Nonzero Source IDs and live
  Source attachment are checked before constructing their Rust representation.
- Translation offsets must be in bounds and at UTF-8 boundaries. `VariantTy`
  sibling traversal is explicitly unsafe outside the safe iterator, whose
  containing type proves that the next delimiter is present. Dictionary entry
  construction rejects nonbasic keys as a type correctness guard.
- Attached channels require owned (`'static`) payloads while preserving local
  non-Send GTK values. Paired thread guards retain both the callback and queued
  values before ordinary channel ownership is released. Foreign finalization
  schedules an idle cleanup on the original context and checks the attaching
  thread before dropping either guard. Missing, cancelled or foreign-thread
  cleanup retains the inert payload instead of destroying thread-bound values.
  This fallback may retain resources; it does not capture a MainContext cycle.

Native library and complete doctest runs cover these corrections, including
partial-construction unwinding, nullable results, typed and scoped bindings,
invalid binding permissions, transform disposal, signed thread limits,
compile-fail lifetime checks, and owner/deferred/cancelled channel cleanup.
The channel controls include an unowned context during foreign idle attachment;
helper-based deferred cleanup does not establish every C finalizer context
behavior. The actual desktop-shell compile also checks compatibility with Tao's
local GTK channel payloads. Original unsafe implementations and resource
exhaustion were not executed to reproduce these defects.

The crate package name, version, dependencies, C ABI and MIT license remain
unchanged. Rust lifetime and retained-data bounds are deliberately tightened
where values can outlive their caller. Charset lookup now returns an owned
string, typed binding inputs must be owned, and direct `VariantTy::next` calls
require the documented unsafe contract. Invalid names, numeric parameters,
indefinite types and nonoptional null wrappers are rejected. No upstream patch,
advisory ID or remote Drive attack path is claimed for these local corrections.

`LICENSE` and `COPYRIGHT` remain from the upstream MIT-licensed source archive.
