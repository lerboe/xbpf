//! Build script support for compiling eBPF programs against the xBPF headers.
//!
//! Everything in this module is meant to be called from a build script.
//! Most of the time [`build`] is enough: it compiles every `*.bpf.c` file
//! below `src` and generates a skeleton for it that [`crate::include_bpf`]
//! can include. [`Builder`] offers the same with more control, and
//! [`tracing_clang_args_from_default_env`] returns just the clang arguments needed
//! to compile a program that uses [`crate::tracing`].
//!
//! How the tracing events are copied to user space can be customized with
//! [`Builder::tracing_ring_buf_size`] and [`Builder::tracing_str_len`], or with the
//! [`tracing_ring_buf_size_args`] and [`tracing_str_len_args`] arguments when driving clang
//! directly.
//!
//! # Example
//!
//! ```no_run
//! # use std::ffi::OsString;
//! # struct SkeletonBuilder;
//! #
//! # impl SkeletonBuilder {
//! #     fn new() -> Self {
//! #         Self
//! #     }
//! #
//! #     fn source(self, _src: &str) -> Self {
//! #         self
//! #     }
//! #
//! #     fn clang_args(self, _args: Vec<OsString>) -> Self {
//! #         self
//! #     }
//! #
//! #     fn build_and_generate(self, _out: &str) -> Result<(), ()> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # let out = "out";
//! # let src = "src";
//! let mut args = vec![OsString::from("-I"), OsString::from("../include")];
//! args.extend(xbpf::build::tracing_clang_args_from_default_env());
//!
//! SkeletonBuilder::new()
//!     .source(&src)
//!     .clang_args(args)
//!     .build_and_generate(&out)
//!     .unwrap();
//! ```
use libbpf_cargo::SkeletonBuilder;
use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};
use tracing::{Dispatch, Level, Metadata, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, registry::Registry};

/// Includes the generated skeleton for the eBPF program with the given name.
///
/// The name is the file name of the eBPF source without its extensions, so
/// `src/syscall_trace.bpf.c` is included as `syscall_trace`. Expanding this
/// brings the `SkelBuilder`, `OpenSkel` and `Skel` types [`crate::Program`]
/// needs into scope.
///
/// ```custom,{.language-rust}
/// xbpf::include_bpf!("syscall_trace");
/// ```
///
/// # Panics
///
/// Fails to compile if no skeleton of that name was generated into `OUT_DIR`,
/// which means the build script didn't call [`build`] or [`Builder::build`].
#[macro_export]
macro_rules! include_bpf {
    ($name:literal) => {
        use xbpf::libbpf_rs;
        include!(concat!(env!("OUT_DIR"), "/", $name, ".skel.rs"));
    };
}

/// A configurable build of the eBPF sources of a crate.
///
/// This is what [`build`] uses underneath, for the cases where its defaults
/// don't fit: another set of source files, extra clang arguments, an explicit
/// output directory, or different tracing settings. Nothing is compiled until
/// [`Builder::build`] or [`Builder::build_objects`] is called.
///
/// # Examples
///
/// ```no_run
/// use xbpf::build::Builder;
///
/// Builder::new()
///     .source("src/bpf/syscall_trace.bpf.c")
///     .clang_arg(["-DMAX_ENTRIES=1024"].iter())
///     .build();
/// ```
pub struct Builder {
    /// The glob pattern used to find source files.
    pattern: String,

    /// The list of explicitely specified source files.
    sources: Vec<PathBuf>,

    /// Additional clang arguments that apply to all jobs.
    clang_args: Vec<OsString>,

    /// The directory generated files are written to, `OUT_DIR` if unset.
    out_dir: Option<PathBuf>,

    /// The tracing level to compile with, derived from `RUST_LOG` if unset.
    #[cfg(feature = "tracing")]
    tracing_level: Option<LevelFilter>,

    /// The value of `BPF_TRACING_RING_BUF_SIZE`, its default if unset.
    #[cfg(feature = "tracing")]
    tracing_ring_buf_size: Option<usize>,

    /// The value of `BPF_TRACING_STR_LEN`, its default if unset.
    #[cfg(feature = "tracing")]
    tracing_str_len: Option<usize>,
}

impl Builder {
    /// Creates a builder that compiles every `*.bpf.c` file below `src`.
    pub fn new() -> Self {
        Self {
            pattern: String::from("src/**/*.bpf.c"),
            sources: Vec::new(),
            clang_args: Vec::new(),
            out_dir: None,
            #[cfg(feature = "tracing")]
            tracing_level: None,
            #[cfg(feature = "tracing")]
            tracing_ring_buf_size: None,
            #[cfg(feature = "tracing")]
            tracing_str_len: None,
        }
    }

    /// Replaces the glob pattern with every file below `src` whose name ends in
    /// `suffix`.
    ///
    /// This is the default pattern with a different suffix, so passing `bpf.c`
    /// restores it. Sources outside of `src` have to be added with
    /// [`Builder::source`].
    pub fn sources_with_suffix<S: ToString>(&mut self, suffix: S) -> &mut Self {
        self.pattern = format!("src/**/*.{}", suffix.to_string());
        self
    }

    /// Adds a source file to compile, on top of the ones the glob pattern
    /// matches.
    ///
    /// The pattern is resolved against the crate root, which is only known
    /// inside a build script, so explicitly added sources are all a caller
    /// outside of one can build.
    pub fn source<P: AsRef<Path>>(&mut self, file: P) -> &mut Self {
        self.sources.push(file.as_ref().to_path_buf());
        self
    }

    /// Adds clang arguments that every source file is compiled with.
    ///
    /// These come after the arguments xBPF passes itself, so they can override
    /// them. The include paths of the kernel BTF and of the xBPF headers are
    /// always passed and don't have to be repeated here.
    pub fn clang_arg<A: AsRef<OsStr>, CA: Iterator<Item = A>>(&mut self, args: CA) -> &mut Self {
        self.clang_args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// Sets the directory that generated files are written to.
    ///
    /// Defaults to `OUT_DIR`, which is only set for build scripts. Callers
    /// outside of a build script, such as tests, have to set it explicitly.
    pub fn out_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.out_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Returns the directory generated files are written to.
    fn get_out_dir(&self) -> PathBuf {
        self.out_dir.clone().unwrap_or_else(|| env_out_dir())
    }

    /// Sets the tracing level the eBPF programs are compiled with.
    ///
    /// Defaults to the level that `RUST_LOG` resolves to for the `bpf` target.
    #[cfg(feature = "tracing")]
    pub fn tracing_level(&mut self, level: LevelFilter) -> &mut Self {
        self.tracing_level = Some(level);
        self
    }

    /// Sets `BPF_TRACING_RING_BUF_SIZE`, the size of the ring buffer the tracing
    /// events are copied through, in bytes. See [`tracing_ring_buf_size_args`].
    #[cfg(feature = "tracing")]
    pub fn tracing_ring_buf_size(&mut self, size: usize) -> &mut Self {
        self.tracing_ring_buf_size = Some(size);
        self
    }

    /// Sets `BPF_TRACING_STR_LEN`, the maximum length of the strings a tracing
    /// event carries, in bytes. See [`tracing_str_len_args`].
    #[cfg(feature = "tracing")]
    pub fn tracing_str_len(&mut self, len: usize) -> &mut Self {
        self.tracing_str_len = Some(len);
        self
    }

    /// Returns every clang argument a job is compiled with, including the ones
    /// needed to find the kernel BTF and the xBPF headers.
    fn all_clang_args(&self) -> Vec<OsString> {
        let btf_include = dump_kernel_btf(self.get_out_dir());
        let mut args = vec![OsString::from("-I"), btf_include.into_os_string()];

        #[cfg(feature = "tracing")]
        {
            args.extend(match self.tracing_level {
                Some(level) => tracing_clang_args(level),
                None => tracing_clang_args_from_default_env(),
            });

            if let Some(size) = self.tracing_ring_buf_size {
                args.extend(tracing_ring_buf_size_args(size));
            }

            if let Some(len) = self.tracing_str_len {
                args.extend(tracing_str_len_args(len));
            }
        }

        args.extend(self.clang_args.iter().cloned());
        args
    }

    /// Returns the directory of `path` relative to the `src` directory of the
    /// crate being built, or [`None`] if it isn't below one.
    fn path_relative_to_src(path: &Path) -> Option<&Path> {
        // The crate root is stripped off first, because it can carry a `src`
        // component of its own.
        let path = Builder::manifest_dir()
            .and_then(|root| path.strip_prefix(root).ok())
            .unwrap_or(path);

        let mut components = path.components();
        for c in &mut components {
            if c.as_os_str() == "src" {
                return components.as_path().parent();
            }
        }
        None
    }

    /// Returns the root of the crate being built, which is only known inside
    /// a build script.
    fn manifest_dir() -> Option<PathBuf> {
        env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)
    }

    /// Returns every source file to compile along with the number of times
    /// its name occurs, which decides whether it can be linked into `out_dir`.
    fn named_sources(&self) -> (Vec<(PathBuf, String)>, HashMap<String, usize>) {
        // The glob pattern is relative to the crate root, so it can only be
        // resolved inside a build script. Everywhere else the explicitly
        // specified sources are all there is to build.
        let globbed = Builder::manifest_dir().map_or_else(Vec::new, |manifest_dir| {
            let pattern = manifest_dir.join(&self.pattern);
            let Some(pattern) = pattern.to_str() else {
                panic!("Invalid eBPF glob pattern: {}", self.pattern);
            };

            let Ok(files) = glob::glob(pattern) else {
                panic!("Invalid eBPF glob pattern: {}", self.pattern);
            };

            files
                .filter_map(|f| match f {
                    Ok(file) => Some(file),
                    Err(e) => {
                        println!("cargo:warning=Failed to read eBPF source file: {:?}", e);
                        None
                    }
                })
                .collect()
        });

        let files = globbed.into_iter().chain(self.sources.clone().into_iter());

        let mut name_counts: HashMap<String, usize> = HashMap::new();
        let named_files: Vec<(PathBuf, String)> = files
            .filter_map(|file| {
                let Some(name) = file.file_prefix() else {
                    println!("cargo:warning=Invalid eBPF source file name: {:?}", file);
                    return None;
                };
                let name = name.to_string_lossy().into_owned();
                *name_counts.entry(name.clone()).or_insert(0) += 1;
                Some((file, name))
            })
            .collect();

        (named_files, name_counts)
    }

    /// Returns the directory the artifacts of `file` are written to, mirroring
    /// the layout the source file has below `src`.
    fn out_subdir(&self, file: &Path) -> PathBuf {
        let rel_dir = Builder::path_relative_to_src(file).unwrap_or(Path::new(""));
        let out_subdir = self.get_out_dir().join(rel_dir);

        if std::fs::create_dir_all(&out_subdir).is_err() {
            panic!(
                "Failed to create output directory: {}",
                out_subdir.display()
            );
        }

        out_subdir
    }

    /// Compiles every source file into an object file and returns their paths.
    ///
    /// Unlike [`Builder::build`] this doesn't generate skeletons, so the
    /// objects have to be loaded at run time, for instance with
    /// [`crate::libbpf_rs::ObjectBuilder`].
    ///
    /// # Panics
    ///
    /// Panics if the glob pattern is invalid, if a source file fails to
    /// compile, or if the output directory cannot be created.
    pub fn build_objects(&self) -> Vec<PathBuf> {
        let clang_args = self.all_clang_args();
        let (named_files, _) = self.named_sources();

        named_files
            .into_iter()
            .map(|(file, name)| {
                println!("cargo:rerun-if-changed={}", file.display());

                let out = self.out_subdir(&file).join(format!("{name}.o"));
                let res = SkeletonBuilder::new()
                    .source(&file)
                    .obj(&out)
                    .clang_args(&clang_args)
                    .build();
                if res.is_err() {
                    panic!("Failed to compile eBPF source file: {:?}: {:?}", file, res);
                }

                out
            })
            .collect()
    }

    /// Exports the xBPF headers so that an IDE can resolve them.
    ///
    /// They are written to [`Builder::out_dir`] if it is set, and to
    /// [`default_header_dir`] otherwise. See [`export_headers`] for what ends
    /// up there.
    pub fn export_headers(&self) -> &Self {
        let dir = if let Some(out_dir) = self.out_dir.clone() {
            out_dir
        } else {
            default_header_dir()
        };

        export_headers(None, dir);
        self
    }

    /// Compiles every source file and generates a skeleton for it that
    /// [`crate::include_bpf`] can include.
    ///
    /// Artifacts mirror the layout their source has below `src`. A skeleton
    /// whose name is unambiguous is additionally symlinked into the root of the
    /// output directory, so that [`crate::include_bpf`] can find it by name
    /// alone.
    ///
    /// # Panics
    ///
    /// Panics if the glob pattern is invalid, if a source file fails to
    /// compile, or if the output directory cannot be created.
    pub fn build(&self) {
        let out_dir = self.get_out_dir();
        let clang_args = self.all_clang_args();
        let (named_files, name_counts) = self.named_sources();

        for (file, name) in named_files {
            println!("cargo:rerun-if-changed={}", file.display());

            let out_subdir = self.out_subdir(&file);
            let skel_name = format!("{}.skel.rs", name);
            let out = out_subdir.join(&skel_name);
            let res = SkeletonBuilder::new()
                .source(&file)
                .clang_args(&clang_args)
                .build_and_generate(&out);
            if res.is_err() {
                panic!("Failed to compile eBPF source file: {:?}: {:?}", file, res);
            }

            if name_counts.get(&name) == Some(&1) && out_subdir != out_dir {
                let link = out_dir.join(&skel_name);
                if link.symlink_metadata().is_ok() {
                    if let Err(e) = std::fs::remove_file(&link) {
                        panic!("Failed to remove stale symlink {:?}: {}", link, e);
                    }
                }
                if let Err(e) = symlink(&out, &link) {
                    println!(
                        "cargo:warning=Failed to create symlink {:?} -> {:?}: {}",
                        link, out, e
                    );
                }
            }
        }
    }
}

/// Compiles every `*.bpf.c` file below `src` and generates a skeleton for it
/// that [`crate::include_bpf`] can include.
///
/// This also exports the xBPF headers to [`default_header_dir`], so that an IDE
/// can be pointed at a single include path. See [`Builder`] for more control.
///
/// # Examples
///
/// ```no_run
/// // build.rs
/// fn main() {
///     xbpf::build();
/// }
/// ```
///
/// # Panics
///
/// Panics if a source file fails to compile, or if `OUT_DIR` is not set, which
/// is the case outside of a build script.
pub fn build() {
    Builder::new().export_headers().build();
}

/// Exports the xBPF headers, along with the additional headers `hdrs`, into
/// `dst`.
///
/// This writes the kernel BTF as a `vmlinux.h` into `dst` along with every
/// header of [`include_path_root`], so that a single include path is enough to
/// resolve what an eBPF source file includes. Pointing an IDE at a directory of
/// its own, rather than at `OUT_DIR`, keeps that path stable enough to write
/// into a `.clangd` file.
///
/// # Panics
///
/// Panics if `bpftool` is missing or fails, or if `dst` cannot be written to.
pub fn export_headers<P: AsRef<Path>>(hdrs: Option<Vec<P>>, dst: P) {
    let dst = dst.as_ref();
    dump_kernel_btf(dst);
    copy_dir(&include_path_root(), dst);

    if let Some(srcs) = hdrs {
        for src in srcs {
            copy_dir(&src.as_ref(), dst);
        }
    }
}

/// Dumps the BTF of the running kernel as a `vmlinux.h` header into `dir` and
/// returns `dir`, so that it can be passed to clang as an include path.
///
/// Dumping is skipped if the header already exists.
///
/// # Panics
///
/// Panics if `bpftool` is not on `PATH`, if dumping the BTF fails, or if the
/// header cannot be written.
pub fn dump_kernel_btf<P: AsRef<Path>>(dir: P) -> PathBuf {
    let dir = dir.as_ref().to_path_buf();
    let vmlinux_path = dir.join("vmlinux.h");

    // TODO: can we validate whether the existing vmlinux.h is up to date with the running kernel?
    if vmlinux_path.exists() {
        return dir;
    }

    if Command::new("bpftool").arg("--version").output().is_err() {
        panic!("bpftool is required to dump kernel BTF but was not found on PATH");
    }

    let output = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .unwrap_or_else(|e| panic!("Failed to run bpftool: {e}"));
    if !output.status.success() {
        panic!(
            "bpftool btf dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    if std::fs::create_dir_all(&dir).is_err() {
        panic!("Failed to create include directory: {}", dir.display());
    }

    std::fs::write(&vmlinux_path, output.stdout)
        .unwrap_or_else(|e| panic!("Failed to write {:?}: {e}", vmlinux_path));

    dir
}

/// Recursively copies the contents of `from` into `to`, overwriting the files
/// that are already there.
fn copy_dir(from: &Path, to: &Path) {
    if let Err(e) = std::fs::create_dir_all(to) {
        panic!("Failed to create directory {}: {e}", to.display());
    }

    let entries = std::fs::read_dir(from)
        .unwrap_or_else(|e| panic!("Failed to read directory {}: {e}", from.display()));

    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("Failed to read entry of {}: {e}", from.display()));
        let src = entry.path();
        let dst = to.join(entry.file_name());

        if src.is_dir() {
            copy_dir(&src, &dst);
        } else if let Err(e) = std::fs::copy(&src, &dst) {
            panic!("Failed to copy {} to {}: {e}", src.display(), dst.display());
        }
    }
}

/// Returns true if `target` is enabled at `level` by this EnvFilter.
fn target_enabled_at(filter: &EnvFilter, target: &'static str, level: Level) -> bool {
    let cs = tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::EVENT, fields: &[]);
    let meta = Metadata::new(
        "probe",
        target,
        level,
        None,
        None,
        None,
        tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(cs)),
        tracing::metadata::Kind::EVENT,
    );

    let dispatch = Dispatch::new(Registry::default().with(filter.clone()));
    dispatch.enabled(&meta)
}

/// Returns the level filter for the given environment variable name.
fn level_from_env(env_var: &str) -> LevelFilter {
    let filter = EnvFilter::builder()
        .with_env_var(env_var)
        .with_default_directive(LevelFilter::OFF.into())
        .from_env_lossy();

    if target_enabled_at(&filter, "bpf", Level::TRACE) {
        LevelFilter::TRACE
    } else if target_enabled_at(&filter, "bpf", Level::DEBUG) {
        LevelFilter::DEBUG
    } else if target_enabled_at(&filter, "bpf", Level::INFO) {
        LevelFilter::INFO
    } else if target_enabled_at(&filter, "bpf", Level::WARN) {
        LevelFilter::WARN
    } else if target_enabled_at(&filter, "bpf", Level::ERROR) {
        LevelFilter::ERROR
    } else {
        LevelFilter::OFF
    }
}

/// Returns the clang arguments used to compile an eBPF program with [`crate::tracing`].
///
/// The vector contains the path to the include directory along with other clang
/// definitions. The log level is determined by the `RUST_LOG`
/// environment variable.
#[inline]
pub fn tracing_clang_args_from_default_env() -> Vec<OsString> {
    tracing_clang_args_from_env(EnvFilter::DEFAULT_ENV)
}

/// Similar to [`tracing_clang_args_from_default_env`], but takes the name of the environment
/// variable that determines the log level.
#[inline]
pub fn tracing_clang_args_from_env(env_var: &str) -> Vec<OsString> {
    println!("cargo:rerun-if-env-changed={env_var}");
    println!("cargo:rerun-if-changed={}", include_path_root().display());
    let level = level_from_env(env_var);

    tracing_clang_args(level)
}

/// Similar to [`tracing_clang_args_from_default_env`], but takes an explicit tracing [`LevelFilter`].
pub fn tracing_clang_args(level: LevelFilter) -> Vec<OsString> {
    let mut args = vec![OsString::from("-I"), OsString::from(include_path_root())];
    let log_level = match level {
        LevelFilter::OFF => 0,
        LevelFilter::ERROR => 1,
        LevelFilter::WARN => 2,
        LevelFilter::INFO => 3,
        LevelFilter::DEBUG => 4,
        LevelFilter::TRACE => 5,
    };
    if log_level == 0 {
        return args;
    }

    let log_level = format!("BPF_TRACING_LEVEL={log_level}");
    args.extend_from_slice(&[OsString::from("-D"), OsString::from(log_level)]);

    if cfg!(feature = "tracing-source-loc") {
        args.extend_from_slice(&[
            OsString::from("-D"),
            OsString::from("BPF_TRACING_SOURCE_LOC=1"),
        ]);
    }

    args
}

/// Returns the clang arguments that set `BPF_TRACING_RING_BUF_SIZE`, the size of
/// the ring buffer the tracing events are copied to user space through.
///
/// The size is given in bytes and must be a power of two multiple of the page
/// size. It defaults to 8192. Events that arrive while the ring buffer is full
/// are dropped, so size it to fit the largest expected burst.
#[inline]
pub fn tracing_ring_buf_size_args(size: usize) -> [OsString; 2] {
    [
        OsString::from("-D"),
        OsString::from(format!("BPF_TRACING_RING_BUF_SIZE={size}")),
    ]
}

/// Returns the clang arguments that set `BPF_TRACING_STR_LEN`, the maximum
/// length of the strings a tracing event carries.
///
/// The length is given in bytes and defaults to 128. Longer messages, and with
/// the `tracing-source-loc` feature longer file names, are truncated to it. It
/// is part of the size of every event, so raising it also raises how much of
/// the ring buffer a single event occupies.
///
/// Note that [`crate::event`] decodes events assuming the default of 128 bytes,
/// so events emitted by a program compiled with a different length are decoded
/// incorrectly.
#[inline]
pub fn tracing_str_len_args(len: usize) -> [OsString; 2] {
    [
        OsString::from("-D"),
        OsString::from(format!("BPF_TRACING_STR_LEN={len}")),
    ]
}

/// Returns the root path of the include directory. Note that arguments returned
/// by [`tracing_clang_args_from_default_env`] and [`tracing_clang_args`] already contain this path.
#[inline]
pub fn include_path_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("include")
}

/// Returns the `OUT_DIR`, or panics if it is not set.
fn env_out_dir() -> PathBuf {
    let Some(dir) = env::var_os("OUT_DIR") else {
        panic!(
            "OUT_DIR must be set to compile eBPF programs. Call `out_dir` when \
             building outside of a build script."
        );
    };
    PathBuf::from(dir)
}

/// Returns the directory the xBPF headers are exported to by default.
///
/// This resolves to the `include` directory next to the profile directories of
/// the target directory, typically `target/include`, so that it is shared by
/// every crate of a workspace and survives a change of profile.
///
/// # Panics
///
/// Panics if `OUT_DIR` is not set, which is the case outside of a build script.
pub fn default_header_dir() -> PathBuf {
    env_out_dir()
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("include")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_with_suffix_matches_default_pattern() {
        let mut builder = Builder::new();
        let default = builder.pattern.clone();

        builder.sources_with_suffix("bpf.c");

        assert_eq!(builder.pattern, default);
    }

    #[test]
    fn mirrors_the_layout_a_source_has_below_the_crate_src() {
        let root = "/home/beekeeper/hive";
        let rel = temp_env::with_var("CARGO_MANIFEST_DIR", Some(root), || {
            let file = PathBuf::from(root).join("src/h1/parser.bpf.c");
            Builder::path_relative_to_src(&file).map(PathBuf::from)
        });

        assert_eq!(rel, Some(PathBuf::from("h1")));
    }

    #[test]
    fn ignores_the_src_directory_of_a_registry_checkout() {
        let root =
            "/home/beekeeper/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hive-0.1.0";
        let rel = temp_env::with_var("CARGO_MANIFEST_DIR", Some(root), || {
            let file = PathBuf::from(root).join("src/h1/parser.bpf.c");
            Builder::path_relative_to_src(&file).map(PathBuf::from)
        });

        assert_eq!(rel, Some(PathBuf::from("h1")));
    }

    #[test]
    fn keeps_a_source_in_the_crate_src_at_the_root() {
        let root = "/home/beekeeper/hive";
        let rel = temp_env::with_var("CARGO_MANIFEST_DIR", Some(root), || {
            let file = PathBuf::from(root).join("src/parser.bpf.c");
            Builder::path_relative_to_src(&file).map(PathBuf::from)
        });

        assert_eq!(rel, Some(PathBuf::new()));
    }

    #[test]
    fn resolves_a_source_given_relative_to_the_crate_root() {
        let rel = temp_env::with_var("CARGO_MANIFEST_DIR", Some("/home/beekeeper/hive"), || {
            Builder::path_relative_to_src(Path::new("src/h1/parser.bpf.c")).map(PathBuf::from)
        });

        assert_eq!(rel, Some(PathBuf::from("h1")));
    }

    #[test]
    fn parse_rich_env_var() {
        let env_var = "TEST_VAR";
        let level = temp_env::with_var(env_var, Some("trace,bpf=debug,other_target=warn"), || {
            level_from_env(env_var)
        });

        assert_eq!(level, LevelFilter::DEBUG);
    }

    #[test]
    fn parse_default_rich_env_var() {
        let env_var = "RUST_LOG";
        let clang_args =
            temp_env::with_var(env_var, Some("trace,bpf=debug,other_target=warn"), || {
                tracing_clang_args_from_default_env()
            });

        assert!(clang_args.contains(&OsString::from("BPF_TRACING_LEVEL=4")));
    }
}
