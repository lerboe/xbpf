//! A port of `bpftool btf dump file <path> format c`.
//!
//! bpftool leaves the C syntax itself to libbpf's `btf_dump` API and only
//! decides the order in which types are dumped, so this does the same: it
//! sorts the types the way bpftool does, dumps them through `btf_dump`, and
//! wraps them in bpftool's boilerplate. The output is byte for byte what
//! bpftool v7.7.0 prints.
use libbpf_rs::libbpf_sys::{
    self, BTF_KIND_ARRAY, BTF_KIND_CONST, BTF_KIND_DECL_TAG, BTF_KIND_ENUM, BTF_KIND_ENUM64,
    BTF_KIND_FLOAT, BTF_KIND_FUNC, BTF_KIND_FUNC_PROTO, BTF_KIND_INT, BTF_KIND_PTR,
    BTF_KIND_RESTRICT, BTF_KIND_STRUCT, BTF_KIND_TYPE_TAG, BTF_KIND_TYPEDEF, BTF_KIND_UNION,
    BTF_KIND_VOLATILE,
};
use std::{
    cell::RefCell,
    cmp::Ordering,
    ffi::{CStr, CString, c_char, c_int, c_void},
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
};

const KFUNC_DECL_TAG: &[u8] = b"bpf_kfunc";
const FASTCALL_DECL_TAG: &[u8] = b"bpf_fastcall";

unsafe extern "C" {
    fn vasprintf(
        strp: *mut *mut c_char,
        fmt: *const c_char,
        ap: *mut libbpf_sys::__va_list_tag,
    ) -> c_int;
    fn free(ptr: *mut c_void);
}

/// Dumps the BTF at `path` as a C header, like `bpftool btf dump file <path>
/// format c` does.
pub(crate) fn dump_btf_c(path: &Path) -> io::Result<Vec<u8>> {
    let btf = Btf::parse(path)?;
    let out = RefCell::new(Vec::new());
    let dump = BtfDump::new(&btf, &out)?;
    let emit = |s: &str| out.borrow_mut().extend_from_slice(s.as_bytes());

    emit("#ifndef __VMLINUX_H__\n");
    emit("#define __VMLINUX_H__\n");
    emit("\n");
    emit("#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n");
    emit(
        "#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)\n",
    );
    emit("#endif\n\n");
    emit("#ifndef __ksym\n");
    emit("#define __ksym __attribute__((section(\".ksyms\")))\n");
    emit("#endif\n\n");
    emit("#ifndef __weak\n");
    emit("#define __weak __attribute__((weak))\n");
    emit("#endif\n\n");
    emit("#ifndef __bpf_fastcall\n");
    emit("#if __has_attribute(bpf_fastcall)\n");
    emit("#define __bpf_fastcall __attribute__((bpf_fastcall))\n");
    emit("#else\n");
    emit("#define __bpf_fastcall\n");
    emit("#endif\n");
    emit("#endif\n\n");

    // Like bpftool, this sorts the void type along with the others and then
    // skips whatever ends up first, rather than skipping the void type itself.
    for id in sorted_type_ids(&btf).into_iter().skip(1) {
        dump.dump_type(id)?;
    }

    emit("\n/* BPF kfuncs */\n");
    emit("#ifndef BPF_NO_KFUNC_PROTOTYPES\n");
    let (kfuncs, fastcalls) = kfuncs(&btf);
    for id in kfuncs {
        emit("extern ");
        if fastcalls.contains(&id) {
            emit("__bpf_fastcall ");
        }
        dump.emit_type_decl(btf.ty(id).type_id(), btf.name(btf.ty(id).name_off()))?;
        emit(" __weak __ksym;\n");
    }
    emit("#endif\n\n");

    emit("#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n");
    emit("#pragma clang attribute pop\n");
    emit("#endif\n");
    emit("\n");
    emit("#endif /* __VMLINUX_H__ */\n");

    drop(dump);
    Ok(out.into_inner())
}

/// A parsed BTF object.
struct Btf(*mut libbpf_sys::btf);

impl Btf {
    fn parse(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `path` is a valid C string.
        let btf = unsafe { libbpf_sys::btf__parse(path.as_ptr(), ptr::null_mut()) };
        if btf.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(btf))
    }

    /// Returns the number of types, including the void type with ID 0.
    fn type_cnt(&self) -> u32 {
        // SAFETY: `self.0` is a valid BTF object.
        unsafe { libbpf_sys::btf__type_cnt(self.0) }
    }

    fn ty(&self, id: u32) -> Type<'_> {
        assert!(id < self.type_cnt(), "invalid BTF type ID {id}");
        // SAFETY: `id` is in range, so this points at a type of `self.0`.
        let t = unsafe { libbpf_sys::btf__type_by_id(self.0, id) };
        Type {
            raw: t.cast(),
            _btf: self,
        }
    }

    /// Returns the name at `name_off`, without the terminating NUL.
    fn name(&self, name_off: u32) -> &CStr {
        // SAFETY: `self.0` is a valid BTF object.
        let name = unsafe { libbpf_sys::btf__name_by_offset(self.0, name_off) };
        if name.is_null() {
            c""
        } else {
            // SAFETY: libbpf returns NUL terminated strings owned by `self.0`.
            unsafe { CStr::from_ptr(name) }
        }
    }
}

impl Drop for Btf {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid BTF object that is freed only here.
        unsafe { libbpf_sys::btf__free(self.0) }
    }
}

/// A BTF type, viewed as the `u32` words of `struct btf_type` and of the data
/// that follows it.
#[derive(Clone, Copy)]
struct Type<'a> {
    raw: *const u32,
    _btf: &'a Btf,
}

impl Type<'_> {
    /// Returns the `i`th `u32` word of the type.
    fn word(&self, i: usize) -> u32 {
        // SAFETY: the callers only read words that are part of the type's
        // kind specific data, which libbpf has validated.
        unsafe { self.raw.add(i).read_unaligned() }
    }

    fn name_off(&self) -> u32 {
        self.word(0)
    }

    fn kind(&self) -> u32 {
        (self.word(1) >> 24) & 0x1f
    }

    fn vlen(&self) -> usize {
        (self.word(1) & 0xffff) as usize
    }

    /// Returns the type this one refers to, for the kinds that refer to one.
    fn type_id(&self) -> u32 {
        self.word(2)
    }

    /// Returns the element type of an array.
    fn array_type(&self) -> u32 {
        self.word(3)
    }

    /// Returns the number of elements of an array.
    fn array_nelems(&self) -> u32 {
        self.word(5)
    }

    /// Returns the name of the `i`th value of an enum.
    fn enum_name_off(&self, i: usize) -> u32 {
        match self.kind() {
            BTF_KIND_ENUM => self.word(3 + 2 * i),
            _ => self.word(3 + 3 * i),
        }
    }

    /// Returns the name and type of the `i`th member of a struct or union.
    fn member(&self, i: usize) -> (u32, u32) {
        (self.word(3 + 3 * i), self.word(4 + 3 * i))
    }

    /// Returns the component index of a decl tag.
    fn decl_tag_component_idx(&self) -> i32 {
        self.word(3) as i32
    }
}

/// A `btf_dump` that appends everything it prints to `out`.
struct BtfDump<'a> {
    raw: *mut libbpf_sys::btf_dump,
    _btf: &'a Btf,
    _out: &'a RefCell<Vec<u8>>,
}

impl<'a> BtfDump<'a> {
    fn new(btf: &'a Btf, out: &'a RefCell<Vec<u8>>) -> io::Result<Self> {
        // SAFETY: `btf.0` is a valid BTF object and `out` outlives the dumper.
        let raw = unsafe {
            libbpf_sys::btf_dump__new(
                btf.0,
                Some(Self::printf),
                ptr::from_ref(out).cast_mut().cast(),
                ptr::null(),
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            raw,
            _btf: btf,
            _out: out,
        })
    }

    unsafe extern "C" fn printf(
        ctx: *mut c_void,
        fmt: *const c_char,
        args: *mut libbpf_sys::__va_list_tag,
    ) {
        // SAFETY: `ctx` is the `out` the dumper was created with.
        let out = unsafe { &*ctx.cast::<RefCell<Vec<u8>>>() };
        let mut s = ptr::null_mut();
        // SAFETY: `fmt` and `args` come straight from libbpf.
        if unsafe { vasprintf(&mut s, fmt, args) } < 0 {
            panic!("Failed to format BTF dump output");
        }
        // SAFETY: `vasprintf` succeeded, so `s` is a NUL terminated string
        // that we own.
        unsafe {
            out.borrow_mut()
                .extend_from_slice(CStr::from_ptr(s).to_bytes());
            free(s.cast());
        }
    }

    fn dump_type(&self, id: u32) -> io::Result<()> {
        // SAFETY: `self.raw` is a valid dumper.
        let err = unsafe { libbpf_sys::btf_dump__dump_type(self.raw, id) };
        check(err)
    }

    fn emit_type_decl(&self, id: u32, field_name: &CStr) -> io::Result<()> {
        // SAFETY: all zeros is the default of every option.
        let mut opts: libbpf_sys::btf_dump_emit_type_decl_opts = unsafe { std::mem::zeroed() };
        opts.sz = size_of_val(&opts) as _;
        opts.field_name = field_name.as_ptr();
        // SAFETY: `self.raw` is a valid dumper and `opts` outlives the call.
        let err = unsafe { libbpf_sys::btf_dump__emit_type_decl(self.raw, id, &opts) };
        check(err)
    }
}

impl Drop for BtfDump<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.raw` is a valid dumper that is freed only here.
        unsafe { libbpf_sys::btf_dump__free(self.raw) }
    }
}

fn check(err: c_int) -> io::Result<()> {
    if err < 0 {
        Err(io::Error::from_raw_os_error(-err))
    } else {
        Ok(())
    }
}

/// The key bpftool sorts the types by.
struct SortDatum<'a> {
    id: u32,
    type_rank: u32,
    sort_name: &'a CStr,
    own_name: &'a CStr,
    disambig_hash: u64,
}

impl SortDatum<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.type_rank
            .cmp(&other.type_rank)
            .then_with(|| self.sort_name.cmp(other.sort_name))
            .then_with(|| self.own_name.cmp(other.own_name))
            .then_with(|| self.disambig_hash.cmp(&other.disambig_hash))
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// Returns the IDs of all types, including the void type, in the order
/// bpftool dumps them.
fn sorted_type_ids(btf: &Btf) -> Vec<u32> {
    let mut datums: Vec<_> = (0..btf.type_cnt())
        .map(|id| SortDatum {
            id,
            type_rank: type_rank(btf, id, false),
            sort_name: type_sort_name(btf, id, false),
            own_name: btf.name(btf.ty(id).name_off()),
            disambig_hash: type_disambig_hash(btf, id, true),
        })
        .collect();
    datums.sort_by(SortDatum::cmp);
    datums.into_iter().map(|d| d.id).collect()
}

fn type_rank(btf: &Btf, id: u32, mut has_name: bool) -> u32 {
    const MAX_RANK: u32 = 10;
    let t = btf.ty(id);

    if t.name_off() != 0 {
        has_name = true;
    }

    match t.kind() {
        BTF_KIND_ENUM | BTF_KIND_ENUM64 => has_name as u32,
        BTF_KIND_INT | BTF_KIND_FLOAT => 2,
        BTF_KIND_STRUCT | BTF_KIND_UNION if has_name => 3,
        BTF_KIND_FUNC_PROTO if has_name => 4,
        BTF_KIND_ARRAY if has_name => type_rank(btf, t.array_type(), has_name),
        BTF_KIND_TYPE_TAG | BTF_KIND_CONST | BTF_KIND_PTR | BTF_KIND_VOLATILE
        | BTF_KIND_RESTRICT | BTF_KIND_TYPEDEF | BTF_KIND_DECL_TAG
            if has_name =>
        {
            type_rank(btf, t.type_id(), has_name)
        }
        _ => MAX_RANK,
    }
}

fn type_sort_name(btf: &Btf, id: u32, from_ref: bool) -> &CStr {
    let t = btf.ty(id);

    match t.kind() {
        BTF_KIND_ENUM | BTF_KIND_ENUM64 => {
            let mut name_off = t.name_off();
            if !from_ref && name_off == 0 && t.vlen() > 0 {
                name_off = t.enum_name_off(0);
            }
            btf.name(name_off)
        }
        BTF_KIND_ARRAY => type_sort_name(btf, t.array_type(), true),
        BTF_KIND_TYPE_TAG | BTF_KIND_CONST | BTF_KIND_PTR | BTF_KIND_VOLATILE
        | BTF_KIND_RESTRICT | BTF_KIND_TYPEDEF | BTF_KIND_DECL_TAG => {
            type_sort_name(btf, t.type_id(), true)
        }
        _ => btf.name(t.name_off()),
    }
}

fn hasher(hash: u64, val: u64) -> u64 {
    hash.wrapping_mul(31).wrapping_add(val)
}

/// libbpf's `str_hash`, which adds up the bytes as `char`s.
fn str_hash(s: &CStr) -> u64 {
    s.to_bytes()
        .iter()
        .fold(0, |h, &b| hasher(h, b as c_char as u64))
}

fn name_hasher(hash: u64, btf: &Btf, name_off: u32) -> u64 {
    if name_off == 0 {
        return hash;
    }
    hasher(hash, str_hash(btf.name(name_off)))
}

fn type_disambig_hash(btf: &Btf, id: u32, include_members: bool) -> u64 {
    let t = btf.ty(id);
    let mut hash = name_hasher(0, btf, t.name_off());

    match t.kind() {
        BTF_KIND_ENUM | BTF_KIND_ENUM64 => {
            for i in 0..t.vlen() {
                hash = name_hasher(hash, btf, t.enum_name_off(i));
            }
        }
        BTF_KIND_STRUCT | BTF_KIND_UNION if include_members => {
            for i in 0..t.vlen() {
                let (name_off, type_id) = t.member(i);
                hash = name_hasher(hash, btf, name_off);
                hash = hasher(hash, type_disambig_hash(btf, type_id, false));
            }
        }
        BTF_KIND_TYPE_TAG | BTF_KIND_CONST | BTF_KIND_PTR | BTF_KIND_VOLATILE
        | BTF_KIND_RESTRICT | BTF_KIND_TYPEDEF | BTF_KIND_DECL_TAG => {
            hash = hasher(hash, type_disambig_hash(btf, t.type_id(), include_members));
        }
        BTF_KIND_ARRAY => {
            hash = hasher(hash, t.array_nelems() as u64);
            hash = hasher(
                hash,
                type_disambig_hash(btf, t.array_type(), include_members),
            );
        }
        _ => {}
    }
    hash
}

/// Returns the IDs of the kfuncs sorted by name, and those of the kfuncs that
/// are also marked `bpf_fastcall`.
fn kfuncs(btf: &Btf) -> (Vec<u32>, Vec<u32>) {
    let mut kfuncs = Vec::new();
    let mut fastcalls = Vec::new();

    for id in 1..btf.type_cnt() {
        let t = btf.ty(id);
        if t.kind() != BTF_KIND_DECL_TAG || t.decl_tag_component_idx() != -1 {
            continue;
        }

        let func_id = t.type_id();
        if btf.ty(func_id).kind() != BTF_KIND_FUNC {
            continue;
        }

        match btf.name(t.name_off()).to_bytes() {
            KFUNC_DECL_TAG => kfuncs.push(func_id),
            FASTCALL_DECL_TAG => fastcalls.push(func_id),
            _ => {}
        }
    }

    kfuncs.sort_by(|&a, &b| {
        btf.name(btf.ty(a).name_off())
            .cmp(btf.name(btf.ty(b).name_off()))
    });
    (kfuncs, fastcalls)
}
