//! Module loader for user scripts: file imports only, with JSON and text attributes.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use deno_core::{
    ModuleLoadOptions, ModuleLoadReferrer, ModuleLoadResponse, ModuleLoader, ModuleResolveResponse,
    ModuleSource, ModuleSourceCode, ModuleSpecifier, ModuleType, RequestedModuleType,
    ResolutionKind, resolve_import,
};
use deno_error::JsErrorBox;

/// Loads `file:` modules and remembers every path it tried, so they can be watched.
pub struct ScriptLoader {
    seen: Rc<RefCell<Vec<PathBuf>>>,
}

impl ScriptLoader {
    pub const fn new(seen: Rc<RefCell<Vec<PathBuf>>>) -> Self {
        Self { seen }
    }
}

impl ModuleLoader for ScriptLoader {
    fn resolve(
        &self,
        specifier: &str,
        referrer: &str,
        _kind: ResolutionKind,
    ) -> ModuleResolveResponse {
        let resolved = resolve_import(specifier, referrer).map_err(JsErrorBox::from_err)?;
        match resolved.scheme() {
            "file" | "ext" | "roxy" => Ok(resolved),
            other => Err(JsErrorBox::type_error(format!(
                "unsupported import scheme {other:?} in {resolved}; only local files can be imported"
            ))),
        }
    }

    fn load(
        &self,
        specifier: &ModuleSpecifier,
        _maybe_referrer: Option<&ModuleLoadReferrer>,
        options: ModuleLoadOptions,
    ) -> ModuleLoadResponse {
        ModuleLoadResponse::Sync(self.load_sync(specifier, &options.requested_module_type))
    }
}

impl ScriptLoader {
    fn load_sync(
        &self,
        specifier: &ModuleSpecifier,
        requested: &RequestedModuleType,
    ) -> Result<ModuleSource, JsErrorBox> {
        let path = specifier
            .to_file_path()
            .map_err(|()| JsErrorBox::type_error(format!("not a file URL: {specifier}")))?;
        self.seen.borrow_mut().push(path.clone());
        let module_type = match requested {
            RequestedModuleType::None => {
                if path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("json"))
                {
                    return Err(JsErrorBox::type_error(format!(
                        "importing JSON requires `with {{ type: \"json\" }}`: {specifier}"
                    )));
                }
                ModuleType::JavaScript
            }
            RequestedModuleType::Json => ModuleType::Json,
            RequestedModuleType::Text => ModuleType::Text,
            RequestedModuleType::Bytes => ModuleType::Bytes,
            RequestedModuleType::Other(other) => {
                return Err(JsErrorBox::type_error(format!(
                    "unsupported import type {other} for {specifier}"
                )));
            }
        };
        // Read exactly once per load: the bytes compiled are the bytes checked.
        let code = std::fs::read(&path)
            .map_err(|e| JsErrorBox::generic(format!("failed to read {}: {e}", path.display())))?;
        Ok(ModuleSource::new(
            module_type,
            ModuleSourceCode::Bytes(code.into_boxed_slice().into()),
            specifier,
            None,
        ))
    }
}
