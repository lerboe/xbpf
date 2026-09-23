/// A trait for types that can be copied byte-for-byte between Rust and eBPF,
/// like the values of an eBPF map or the context of a syscall program.
///
/// The types libbpf-cargo generates for a skeleton don't implement it, because
/// they can hold a `bool`, which isn't valid for every bit pattern. Implement
/// it for the ones that are:
///
/// ```ignore
/// unsafe impl xbpf::Pod for types::args {}
/// ```
///
/// # Safety
///
/// Implementors must guarantee that the type has no padding bytes, is valid
/// for any bit pattern of its size, and matches the memory layout of the C
/// type used on the eBPF side.
pub unsafe trait Pod: Copy + 'static {}

macro_rules! impl_pod {
    ($($t:ty),* $(,)?) => {
        $(unsafe impl Pod for $t {})*
    };
}

impl_pod!(
    u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize, f32, f64
);

unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}
