//! Stand-in for `deno_net`, shared with `build.rs` so it lands in the startup snapshot.

// deno_fetch lazily imports this script even though only Deno.createHttpClient uses it.
deno_core::extension!(
    deno_net,
    lazy_loaded_js = [dir "src/engine/stubs", "02_tls.js"],
);
