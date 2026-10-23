//! The startup snapshot `build.rs` generates, and the lazy sources it left out.

pub static SNAPSHOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/snapshot.bin"));

include!(concat!(env!("OUT_DIR"), "/residual.rs"));
