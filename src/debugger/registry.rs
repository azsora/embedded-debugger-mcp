//! Custom chip registry management
//!
//! Loads custom chip definitions from YAML files at startup.
//! Uses probe-rs Registry API to add custom chips without modifying the library.

use probe_rs::config::Registry;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Global custom chip registry storage
/// Initialized at startup with builtin chips, then custom chips are added via add_target_family_from_yaml
pub static CUSTOM_REGISTRY: std::sync::LazyLock<Arc<RwLock<Registry>>> =
    std::sync::LazyLock::new(|| Arc::new(RwLock::new(Registry::from_builtin_families())));

/// Initialize the custom chip registry by loading YAML files from the specified directory
pub fn init_custom_registry(chip_dir: &std::path::Path) -> Result<(), String> {
    info!("Loading custom chips from {}", chip_dir.display());

    // Check if directory exists
    if !chip_dir.exists() {
        warn!("Custom chip directory does not exist: {}", chip_dir.display());
        return Ok(());
    }

    // Collect all YAML file paths first (to release directory handle early)
    let yaml_paths: Vec<_> = std::fs::read_dir(chip_dir)
        .map_err(|e| format!("Failed to read chip directory: {}", e))?
        .flatten()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("yaml"))
        .map(|e| e.path())
        .collect();

    // Acquire write lock to add families (blocking, OK since we're in sync init context)
    let mut reg_write = futures::executor::block_on(CUSTOM_REGISTRY.write());
    let mut loaded_families = 0;

    for path in yaml_paths {
        info!("Loading chip definition from: {}", path.display());
        match std::fs::read_to_string(&path) {
            Ok(yaml_content) => {
                match reg_write.add_target_family_from_yaml(&yaml_content) {
                    Ok(family_name) => {
                        loaded_families += 1;
                        info!("Loaded chip family: {}", family_name);
                    }
                    Err(e) => {
                        error!("Failed to load {}: {}", path.display(), e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to read {}: {}", path.display(), e);
            }
        }
    }

    info!("Custom chip registry initialized: {} families", loaded_families);
    Ok(())
}