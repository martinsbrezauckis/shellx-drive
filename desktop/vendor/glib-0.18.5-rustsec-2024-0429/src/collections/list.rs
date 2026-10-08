// Take a look at the license at the top of the repository in the LICENSE file.

use std::{iter::FusedIterator, marker::PhantomData, mem, ptr};

use crate::translate::*;

// rustdoc-stripper-ignore-next
/// A list of items of type `T`.
///
/// Behaves like an `Iterator<Item = T>` but allows modifications.
#[repr(transparent)]
pub struct List<T: TransparentPtrType> {
    ptr: Option<ptr::NonNull<ffi::GList>>,
    phantom: PhantomData<T>,
}

#[doc(hidden)]
unsafe impl<T: TransparentPtrType> TransparentPtrType for List<T> {}

#[doc(hidden)]
impl<T: TransparentPtrType> GlibPtrDefault for List<T> {
    type GlibType = *mut ffi::GList;
}

unsafe impl<T: Send + TransparentPtrType> Send for List<T> {}

unsafe impl<T: Sync + TransparentPtrType> Sync for List<T> {}

impl<T: TransparentPtrType> List<T> {
    // rustdoc-stripper-ignore-next
    /// Create a new `List` around a list.
    #[inline]
    pub unsafe fn from_glib_none(list: *const ffi::GList) -> List<T> {
        // Need to copy the whole list
        let list = if mem::needs_drop::<T>() {
            unsafe extern "C" fn copy_item<T: TransparentPtrType>(
                ptr: ffi::gconstpointer,
                _user_data: ffi::gpointer,
            ) -> ffi::gpointer {
                let mut item = mem::ManuallyDrop::new(
                    (*(&ptr as *const ffi::gconstpointer as *const T)).clone(),
                );

                *(&mut *item as *mut T as *mut *mut T::GlibType) as ffi::gpointer
            }

            ffi::g_list_copy_deep(mut_override(list), Some(copy_item::<T>), ptr::null_mut())
        } else {
            ffi::g_list_copy(mut_override(list))
        };

        List {
            ptr: ptr::NonNull::new(list),
            phantom: PhantomData,
        }
    }

    // rustdoc-stripper-ignore-next
    /// Create a new `List` around a list.
    #[inline]
    pub unsafe fn from_glib_container(list: *mut ffi::GList) -> List<T> {
        // Need to copy all items as we only own the container
        if mem::needs_drop::<T>() {
            unsafe extern "C" fn copy_item<T: TransparentPtrType>(
                ptr: ffi::gpointer,
                _user_data: ffi::gpointer,
            ) {
                let item = (*(&ptr as *const ffi::gpointer as *const T)).clone();
                ptr::write(ptr as *mut T, item);
            }

            ffi::g_list_foreach(list, Some(copy_item::<T>), ptr::null_mut());
        }

        List {
            ptr: ptr::NonNull::new(list),
            phantom: PhantomData,
        }
    }

    // rustdoc-stripper-ignore-next
    /// Create a new `List` around a list.
    #[inline]
    pub unsafe fn from_glib_full(list: *mut ffi::GList) -> List<T> {
        List {
            ptr: ptr::NonNull::new(list),
            phantom: PhantomData,
        }
    }

    // rustdoc-stripper-ignore-next
    /// Creates a new empty list.
    #[inline]
    pub fn new() -> Self {
        List {
            ptr: None,
            phantom: PhantomData,
        }
    }

    // rustdoc-stripper-ignore-next
    /// Create a non-destructive iterator over the `List`.
    #[inline]
    pub fn iter(&self) -> Iter<T> {
        Iter::new(self)
    }

    // rustdoc-stripper-ignore-next
    /// Create a non-destructive mutable iterator over the `List`.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<T> {
        IterMut::new(self)
    }

    // rustdoc-stripper-ignore-next
    /// Check if the list is empty.
    ///
    /// This operation is `O(1)`.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ptr.is_none()
    }

    // rustdoc-stripper-ignore-next
    /// Returns the length of the list.
    ///
    /// This operation is `O(n)`.
    #[inline]
    #[doc(alias = "g_list_length")]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    // rustdoc-stripper-ignore-next
    /// Returns a reference to the first item of the list, if any.
    ///
    /// This operation is `O(1)`.
    #[inline]
    #[doc(alias = "g_list_first")]
    pub fn front(&self) -> Option<&T> {
        match self.ptr {
            None => None,
            Some(cur) => unsafe {
                let item = &*(&cur.as_ref().data as *const ffi::gpointer as *const T);
                Some(item)
            },
        }
    }

    // rustdoc-stripper-ignore-next
    /// Returns a mutable reference to the first item of the list, if any.
    ///
    /// This operation is `O(1)`.
    #[inline]
    #[doc(alias = "g_list_first")]
    pub fn front_mut(&mut self) -> Option<&mut T> {
        match self.ptr {
            None => None,
            Some(mut cur) => unsafe {
                let item = &mut *(&mut cur.as_mut().data as *mut ffi::gpointer as *mut T);
                Some(item)
            },
        }
    }

    // rustdoc-stripper-ignore-next
    /// Removes the front item from the list, if any.
    ///
    /// This operation is `O(1)`.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        match self.ptr {
            None => None,
            Some(mut cur) => unsafe {
                self.ptr = ptr::NonNull::new(cur.as_ref().next);
                if let Some(mut next) = self.ptr {
                    next.as_mut().prev = ptr::null_mut();
                }

                let item = ptr::read(&mut cur.as_mut().data as *mut ffi::gpointer as *mut T);

                ffi::g_list_free_1(cur.as_ptr());

                Some(item)
            },
        }
    }

    // rustdoc-stripper-ignore-next
    /// Prepends the new item to the front of the list.
    ///
    /// This operation is `O(1)`.
    #[inline]
    #[doc(alias = "g_list_prepend")]
    pub fn push_front(&mut self, item: T) {
        unsafe {
            let ptr = self.ptr.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut());
            self.ptr = Some(ptr::NonNull::new_unchecked(ffi::g_list_prepend(
                ptr,
                *(&mut *mem::ManuallyDrop::new(item) as *mut T as *mut *mut T::GlibType)
                    as ffi::gpointer,
            )));
        }
    }

    // rustdoc-stripper-ignore-next
    /// Returns a reference to the last item of the list, if any.
    ///
    /// This operation is `O(n)`.
    #[inline]
    #[doc(alias = "g_list_last")]
    pub fn back(&self) -> Option<&T> {
        unsafe {
            let ptr = match self.ptr {
                None => return None,
                Some(ptr) => ptr.as_ptr(),
            };
            let last_ptr = ffi::g_list_last(ptr);
            let item = &*(&(*last_ptr).data as *const ffi::gpointer as *const T);
            Some(item)
        }
    }

    // rustdoc-stripper-ignore-next
    /// Returns a mutable reference to the last item of the list, if any.
    ///
    /// This operation is `O(n)`.
    #[inline]
    #[doc(alias = "g_list_last")]
    pub fn back_mut(&mut self) -> Option<&mut T> {
        unsafe {
            let ptr = match self.ptr {
                None => return None,
                Some(ptr) => ptr.as_ptr(),
            };
            let last_ptr = ffi::g_list_last(ptr);
            let item = &mut *(&mut (*last_ptr).data as *mut ffi::gpointer as *mut T);
            Some(item)
        }
    }

    // rustdoc-stripper-ignore-next
    /// Removes the back item from the list, if any.
    ///
    /// This operation is `O(n)`.
    #[inline]
    pub fn pop_back(&mut self) -> Option<T> {
        unsafe {
            let ptr = match self.ptr {
                None => return None,
                Some(ptr) => ptr.as_ptr(),
            };
            let last_ptr = ffi::g_list_last(ptr);
            let item = ptr::read(&mut (*last_ptr).data as *mut ffi::gpointer as *mut T);
            self.ptr = ptr::NonNull::new(ffi::g_list_delete_link(ptr, last_ptr));

            Some(item)
        }
    }

    // rustdoc-stripper-ignore-next
    /// Appends the new item to the back of the list.
    ///
    /// this operation is `O(n)`.
    #[inline]
    #[doc(alias = "g_list_append")]
    pub fn push_back(&mut self, item: T) {
        unsafe {
            let ptr = self.ptr.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut());
            self.ptr = Some(ptr::NonNull::new_unchecked(ffi::g_list_append(
                ptr,
                *(&mut *mem::ManuallyDrop::new(item) as *mut T as *mut *mut T::GlibType)
                    as ffi::gpointer,
            )));
        }
    }

    // rustdoc-stripper-ignore-next
    /// Reverse the list.
    ///
    /// This operation is `O(n)`.
    #[inline]
    #[doc(alias = "g_list_reverse")]
    pub fn reverse(&mut self) {
        unsafe {
            let ptr = match self.ptr {
                None => return,
                Some(ptr) => ptr.as_ptr(),
            };

            self.ptr = Some(ptr::NonNull::new_unchecked(ffi::g_list_reverse(ptr)));
        }
    }

    // rustdoc-stripper-ignore-next
    /// Sorts the list.
    ///
    /// This operation is `O(n * log n)`.
    #[inline]
    #[doc(alias = "g_list_sort")]
    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.sort_by(|a, b| a.cmp(b));
    }

    // rustdoc-stripper-ignore-next
    /// Sorts the list.
    ///
    /// This operation is `O(n * log n)`.
    #[inline]
    #[doc(alias = "g_list_sort")]
    pub fn sort_by<F: FnMut(&T, &T) -> std::cmp::Ordering>(&mut self, mut f: F) {
        unsafe {
            let ptr = match self.ptr {
                None => return,
                Some(ptr) => ptr.as_ptr(),
            };

            unsafe extern "C" fn func<
                T: TransparentPtrType,
                F: FnMut(&T, &T) -> std::cmp::Ordering,
            >(
                a: ffi::gconstpointer,
                b: ffi::gconstpointer,
                user_data: ffi::gpointer,
            ) -> i32 {
                let f = &mut *(user_data as *mut F);
                let a = &*(&a as *const ffi::gconstpointer as *const T);
                let b = &*(&b as *const ffi::gconstpointer as *const T);
                f(a, b).into_glib()
            }

            self.ptr = Some(ptr::NonNull::new_unchecked(ffi::g_list_sort_with_data(
                ptr,
                Some(func::<T, F>),
                &mut f as *mut F as ffi::gpointer,
            )));
        }
    }

    // rustdoc-stripper-ignore-next
    /// Removes all items from the list.
    #[inline]
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    // rustdoc-stripper-ignore-next
    /// Only keeps the item in the list for which `f` returns `true`.
    #[inline]
    pub fn retain(&mut self, mut f: impl FnMut(&T) -> bool) {
        if let Some(head) = self.ptr {
            unsafe {
                let mut ptr = head.as_ptr();
                while !ptr.is_null() {
                    let item = &*(&(*ptr).data as *const ffi::gpointer as *const T);
                    let next = (*ptr).next;
                    if !f(item) {
                        let removed = ptr::read(&(*ptr).data as *const ffi::gpointer as *const T);
                        self.ptr = ptr::NonNull::new(ffi::g_list_delete_link(
                            self.ptr.unwrap().as_ptr(),
                            ptr,
                        ));
                        // A panicking destructor must not leave a freed value in the live list.
                        drop(removed);
                    }
                    ptr = next;
                }
            }
        }
    }

    // rustdoc-stripper-ignore-next
    /// Returns the underlying pointer.
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::GList {
        self.ptr.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut())
    }

    // rustdoc-stripper-ignore-next
    /// Returns the underlying pointer.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::GList {
        self.ptr.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut())
    }

    // rustdoc-stripper-ignore-next
    /// Consumes the list and returns the underlying pointer.
    #[inline]
    pub fn into_raw(mut self) -> *mut ffi::GList {
        self.ptr
            .take()
            .map(|p| p.as_ptr())
            .unwrap_or(ptr::null_mut())
    }
}

impl<T: TransparentPtrType> Default for List<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TransparentPtrType> Clone for List<T> {
    fn clone(&self) -> Self {
        unsafe { Self::from_glib_none(self.ptr.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut())) }
    }
}

impl<T: TransparentPtrType> Drop for List<T> {
    #[inline]
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr {
            unsafe {
                if mem::needs_drop::<T>() {
                    unsafe extern "C" fn drop_item<T: TransparentPtrType>(mut ptr: ffi::gpointer) {
                        ptr::drop_in_place(&mut ptr as *mut ffi::gpointer as *mut T);
                    }

                    ffi::g_list_free_full(ptr.as_ptr(), Some(drop_item::<T>));
                } else {
                    ffi::g_list_free(ptr.as_ptr());
                }
            }
        }
    }
}

impl<T: TransparentPtrType> std::iter::FromIterator<T> for List<T> {
    #[inline]
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        unsafe {
            let mut iter = iter.into_iter();

            let first = match iter.next() {
                None => return Self::new(),
                Some(first) => first,
            };

            let list = ffi::g_list_prepend(
                ptr::null_mut(),
                *(&mut *mem::ManuallyDrop::new(first) as *mut T as *mut *mut T::GlibType)
                    as ffi::gpointer,
            );
            let mut tail = list;
            for item in iter {
                let new_tail = ffi::g_list_alloc();

                (*new_tail).data = *(&mut *mem::ManuallyDrop::new(item) as *mut T
                    as *mut *mut T::GlibType) as ffi::gpointer;
                (*new_tail).prev = tail;
                (*new_tail).next = ptr::null_mut();
                (*tail).next = new_tail;
                tail = new_tail;
            }

            Self::from_glib_full(list)
        }
    }
}

impl<'a, T: TransparentPtrType> std::iter::IntoIterator for &'a List<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: TransparentPtrType> std::iter::IntoIterator for &'a mut List<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T: TransparentPtrType> std::iter::IntoIterator for List<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self)
    }
}

impl<T: TransparentPtrType> FromGlibContainer<<T as GlibPtrDefault>::GlibType, *mut ffi::GList>
    for List<T>
{
    #[inline]
    unsafe fn from_glib_none_num(ptr: *mut ffi::GList, _num: usize) -> Self {
        Self::from_glib_none(ptr)
    }

    #[inline]
    unsafe fn from_glib_container_num(ptr: *mut ffi::GList, _num: usize) -> Self {
        Self::from_glib_container(ptr)
    }

    #[inline]
    unsafe fn from_glib_full_num(ptr: *mut ffi::GList, _num: usize) -> Self {
        Self::from_glib_full(ptr)
    }
}

impl<T: TransparentPtrType> FromGlibContainer<<T as GlibPtrDefault>::GlibType, *const ffi::GList>
    for List<T>
{
    #[inline]
    unsafe fn from_glib_none_num(ptr: *const ffi::GList, _num: usize) -> Self {
        Self::from_glib_none(ptr)
    }

    unsafe fn from_glib_container_num(_ptr: *const ffi::GList, _num: usize) -> Self {
        unimplemented!();
    }

    unsafe fn from_glib_full_num(_ptr: *const ffi::GList, _num: usize) -> Self {
        unimplemented!();
    }
}

impl<T: TransparentPtrType> FromGlibPtrContainer<<T as GlibPtrDefault>::GlibType, *mut ffi::GList>
    for List<T>
{
    #[inline]
    unsafe fn from_glib_none(ptr: *mut ffi::GList) -> Self {
        Self::from_glib_none(ptr)
    }

    #[inline]
    unsafe fn from_glib_container(ptr: *mut ffi::GList) -> Self {
        Self::from_glib_container(ptr)
    }

    #[inline]
    unsafe fn from_glib_full(ptr: *mut ffi::GList) -> Self {
        Self::from_glib_full(ptr)
    }
}

impl<T: TransparentPtrType> FromGlibPtrContainer<<T as GlibPtrDefault>::GlibType, *const ffi::GList>
    for List<T>
{
    #[inline]
    unsafe fn from_glib_none(ptr: *const ffi::GList) -> Self {
        Self::from_glib_none(ptr)
    }

    unsafe fn from_glib_container(_ptr: *const ffi::GList) -> Self {
        unimplemented!();
    }

    unsafe fn from_glib_full(_ptr: *const ffi::GList) -> Self {
        unimplemented!();
    }
}

impl<'a, T: TransparentPtrType + 'a> ToGlibPtr<'a, *mut ffi::GList> for List<T> {
    type Storage = PhantomData<&'a Self>;

    #[inline]
    fn to_glib_none(&'a self) -> Stash<'a, *mut ffi::GList, Self> {
        Stash(self.as_ptr() as *mut _, PhantomData)
    }

    #[inline]
    fn to_glib_container(&'a self) -> Stash<'a, *mut ffi::GList, Self> {
        unsafe {
            let ptr = ffi::g_list_copy(self.as_ptr() as *mut _);
            Stash(ptr, PhantomData)
        }
    }

    #[inline]
    fn to_glib_full(&self) -> *mut ffi::GList {
        self.clone().into_raw()
    }
}

impl<'a, T: TransparentPtrType + 'a> ToGlibPtr<'a, *const ffi::GList> for List<T> {
    type Storage = PhantomData<&'a Self>;

    #[inline]
    fn to_glib_none(&'a self) -> Stash<'a, *const ffi::GList, Self> {
        Stash(self.as_ptr(), PhantomData)
    }
}

impl<'a, T: TransparentPtrType + 'a> ToGlibPtrMut<'a, *mut ffi::GList> for List<T> {
    type Storage = PhantomData<&'a mut Self>;

    #[inline]
    fn to_glib_none_mut(&'a mut self) -> StashMut<'a, *mut ffi::GList, Self> {
        StashMut(self.as_mut_ptr(), PhantomData)
    }
}

impl<T: TransparentPtrType> IntoGlibPtr<*mut ffi::GList> for List<T> {
    #[inline]
    unsafe fn into_glib_ptr(self) -> *mut ffi::GList {
        self.into_raw()
    }
}

// rustdoc-stripper-ignore-next
/// A non-destructive iterator over a [`List`].
pub struct Iter<'a, T: TransparentPtrType> {
    ptr: Option<ptr::NonNull<ffi::GList>>,
    phantom: PhantomData<&'a T>,
}

impl<'a, T: TransparentPtrType> Iter<'a, T> {
    #[inline]
    fn new(list: &'a List<T>) -> Iter<'a, T> {
        debug_assert_eq!(
            mem::size_of::<T>(),
            mem::size_of::<<T as GlibPtrDefault>::GlibType>()
        );

        Iter {
            ptr: list.ptr,
            phantom: PhantomData,
        }
    }
}

impl<'a, T: TransparentPtrType> Iterator for Iter<'a, T> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<&'a T> {
        match self.ptr {
            None => None,
            Some(cur) => unsafe {
                self.ptr = ptr::NonNull::new(cur.as_ref().next);

                let item = &*(&cur.as_ref().data as *const ffi::gpointer as *const T);

                Some(item)
            },
        }
    }
}

impl<'a, T: TransparentPtrType> FusedIterator for Iter<'a, T> {}

// rustdoc-stripper-ignore-next
/// A non-destructive iterator over a [`List`].
pub struct IterMut<'a, T: TransparentPtrType> {
    ptr: Option<ptr::NonNull<ffi::GList>>,
    phantom: PhantomData<&'a mut T>,
}

impl<'a, T: TransparentPtrType> IterMut<'a, T> {
    #[inline]
    fn new(list: &'a mut List<T>) -> IterMut<'a, T> {
        debug_assert_eq!(
            mem::size_of::<T>(),
            mem::size_of::<<T as GlibPtrDefault>::GlibType>()
        );

        IterMut {
            ptr: list.ptr,
            phantom: PhantomData,
        }
    }
}

impl<'a, T: TransparentPtrType> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    #[inline]
    fn next(&mut self) -> Option<&'a mut T> {
        match self.ptr {
            None => None,
            Some(mut cur) => unsafe {
                self.ptr = ptr::NonNull::new(cur.as_ref().next);

                let item = &mut *(&mut cur.as_mut().data as *mut ffi::gpointer as *mut T);

                Some(item)
            },
        }
    }
}

impl<'a, T: TransparentPtrType> FusedIterator for IterMut<'a, T> {}

// rustdoc-stripper-ignore-next
/// A destructive iterator over a [`List`].
pub struct IntoIter<T: TransparentPtrType> {
    list: List<T>,
}

impl<T: TransparentPtrType> IntoIter<T> {
    #[inline]
    fn new(list: List<T>) -> IntoIter<T> {
        debug_assert_eq!(
            mem::size_of::<T>(),
            mem::size_of::<<T as GlibPtrDefault>::GlibType>()
        );

        IntoIter { list }
    }
}

impl<T: TransparentPtrType> Iterator for IntoIter<T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<T> {
        self.list.pop_front()
    }
}

impl<T: TransparentPtrType> FusedIterator for IntoIter<T> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prelude::ObjectExt;

    type DropState = (usize, std::rc::Rc<std::cell::RefCell<Vec<usize>>>, bool);

    #[derive(Clone)]
    #[repr(transparent)]
    struct DropOwner(Box<DropState>);

    impl GlibPtrDefault for DropOwner {
        type GlibType = *mut DropState;
    }

    // Box<DropState> has the same representation as its non-null allocation pointer.
    unsafe impl TransparentPtrType for DropOwner {}

    impl Drop for DropOwner {
        fn drop(&mut self) {
            self.0 .1.borrow_mut().push(self.0 .0);
            assert!(!self.0 .2, "element destructor failed");
        }
    }

    #[test]
    fn retain_drop_panic_leaves_only_live_nodes() {
        for removed_id in [0, 1] {
            let drops = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let mut items = List::new();
            for id in 0..3 {
                items.push_back(DropOwner(Box::new((id, drops.clone(), id == removed_id))));
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                items.retain(|item| item.0 .0 != removed_id);
            }));
            assert!(result.is_err());
            let survivors = (0..3).filter(|id| *id != removed_id).collect::<Vec<_>>();
            assert_eq!(
                items.iter().map(|item| item.0 .0).collect::<Vec<_>>(),
                survivors
            );
            assert_eq!(*drops.borrow(), [removed_id]);
            items.push_back(DropOwner(Box::new((3, drops.clone(), false))));
            items.retain(|_| false);
            assert!(items.is_empty());
            let mut actual = drops.borrow().clone();
            actual.sort_unstable();
            assert_eq!(actual, [0, 1, 2, 3]);
        }
    }

    #[test]
    fn retain_reads_each_element() {
        let mut list = (10..14)
            .map(|second| crate::DateTime::from_utc(2021, 11, 20, 23, 41, second as f64).unwrap())
            .collect::<List<_>>();
        let mut visited = Vec::new();
        list.retain(|item| {
            visited.push(item.second());
            item.second() % 2 == 0
        });
        assert_eq!(visited, [10, 11, 12, 13]);
        assert_eq!(
            list.iter().map(|item| item.second()).collect::<Vec<_>>(),
            [10, 12]
        );
    }

    #[test]
    fn retain_removes_consecutive_heads_and_all_remaining() {
        let mut list = (0..4)
            .map(|_| crate::Object::new::<crate::Object>())
            .collect::<List<_>>();
        let weak = list.iter().map(|item| item.downgrade()).collect::<Vec<_>>();
        let mut visited = 0;
        list.retain(|_| {
            visited += 1;
            visited > 2
        });
        assert_eq!(visited, 4);
        assert_eq!(list.len(), 2);
        assert!(weak[..2].iter().all(|item| item.upgrade().is_none()));
        assert!(weak[2..].iter().all(|item| item.upgrade().is_some()));
        list.retain(|_| false);
        assert!(list.is_empty());
        assert!(weak.iter().all(|item| item.upgrade().is_none()));
    }

    #[test]
    fn container_copy_has_independent_nodes_and_borrowed_elements() {
        let list = (0..3)
            .map(|_| crate::Object::new::<crate::Object>())
            .collect::<List<_>>();
        let weak = list.iter().map(|item| item.downgrade()).collect::<Vec<_>>();
        let copy = ToGlibPtr::<*mut ffi::GList>::to_glib_container(&list);
        unsafe {
            let mut original = list.as_ptr();
            let mut copied = copy.0;
            let mut previous = ptr::null_mut();
            while !original.is_null() {
                assert!(!copied.is_null());
                assert_ne!(original, copied as *const _);
                assert_eq!((*original).data, (*copied).data);
                assert_eq!((*copied).prev, previous);
                previous = copied;
                original = (*original).next;
                copied = (*copied).next;
            }
            assert!(copied.is_null());
            let tail = ffi::g_list_delete_link(copy.0, copy.0);
            ffi::g_list_free(tail);
        }
        assert_eq!(list.len(), 3);
        assert!(weak.iter().all(|item| item.upgrade().is_some()));
        drop(list);
        assert!(weak.iter().all(|item| item.upgrade().is_none()));
    }

    #[test]
    fn container_copy_of_empty_list_is_null() {
        let list = List::<crate::Object>::new();
        let copy = ToGlibPtr::<*mut ffi::GList>::to_glib_container(&list);
        assert!(copy.0.is_null());
    }

    #[test]
    // checker-ignore-item
    fn from_glib_full() {
        let items = [
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 12.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 13.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 14.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 15.0).unwrap(),
        ];
        let mut list = unsafe {
            let mut list = ffi::g_list_append(
                ptr::null_mut(),
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_full(&items[0]) as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_full(&items[1]) as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_full(&items[2]) as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_full(&items[3]) as ffi::gpointer,
            );
            List::<crate::DateTime>::from_glib_full(list)
        };
        assert!(!list.is_empty());

        let list_items = list.iter().cloned().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list_items = list.iter_mut().map(|d| d.clone()).collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list_items = list.into_iter().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list = unsafe { List::<crate::DateTime>::from_glib_full(ptr::null_mut()) };
        assert!(list.is_empty());
    }

    #[test]
    // checker-ignore-item
    fn from_glib_container() {
        let items = [
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 12.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 13.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 14.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 15.0).unwrap(),
        ];
        let mut list = unsafe {
            let mut list = ffi::g_list_append(
                ptr::null_mut(),
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[0]).0 as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[1]).0 as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[2]).0 as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[3]).0 as ffi::gpointer,
            );
            List::<crate::DateTime>::from_glib_container(list)
        };
        assert!(!list.is_empty());

        let list_items = list.iter().cloned().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list_items = list.iter_mut().map(|d| d.clone()).collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list_items = list.into_iter().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list = unsafe { List::<crate::DateTime>::from_glib_full(ptr::null_mut()) };
        assert!(list.is_empty());
    }

    #[test]
    // checker-ignore-item
    fn from_glib_none() {
        let items = [
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 12.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 13.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 14.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 15.0).unwrap(),
        ];
        let mut list = unsafe {
            let mut list = ffi::g_list_append(
                ptr::null_mut(),
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[0]).0 as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[1]).0 as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[2]).0 as ffi::gpointer,
            );
            list = ffi::g_list_append(
                list,
                ToGlibPtr::<*mut ffi::GDateTime>::to_glib_none(&items[3]).0 as ffi::gpointer,
            );
            let res = List::<crate::DateTime>::from_glib_none(list);
            ffi::g_list_free(list);

            res
        };
        assert!(!list.is_empty());

        let list_items = list.iter().cloned().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list_items = list.iter_mut().map(|d| d.clone()).collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list_items = list.into_iter().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        let list = unsafe { List::<crate::DateTime>::from_glib_full(ptr::null_mut()) };
        assert!(list.is_empty());
    }

    #[test]
    // checker-ignore-item
    fn safe_api() {
        let items = [
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 12.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 13.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 14.0).unwrap(),
            crate::DateTime::from_utc(2021, 11, 20, 23, 41, 15.0).unwrap(),
        ];

        let mut list = items[1..3].iter().cloned().collect::<List<_>>();
        assert_eq!(list.len(), 2);
        list.push_front(items[0].clone());
        assert_eq!(list.len(), 3);
        list.push_back(items[3].clone());
        assert_eq!(list.len(), 4);

        let list_items = list.iter().cloned().collect::<Vec<_>>();
        assert_eq!(&items[..], &list_items);

        assert_eq!(list.front(), Some(&items[0]));
        assert_eq!(list.back(), Some(&items[3]));
        assert_eq!(list.pop_front().as_ref(), Some(&items[0]));
        assert_eq!(list.len(), 3);

        list.reverse();
        let mut list_items = list.iter().cloned().collect::<Vec<_>>();
        list_items.reverse();
        assert_eq!(&items[1..], &list_items);

        let list2 = list.clone();
        let mut list_items = list2.iter().cloned().collect::<Vec<_>>();
        list_items.reverse();
        assert_eq!(&items[1..], &list_items);
    }
}
