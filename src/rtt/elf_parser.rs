//! ELF symbol parsing using object crate
//!
//! Provides ELF file parsing and symbol table access for RTT control block detection.

use crate::error::{DebugError, Result};
use object::{File, Object, ObjectSection, ObjectSymbol};
use std::path::Path;
use tracing::{debug, info, warn};

/// RTT symbol name as defined by SEGGER RTT implementation
const RTT_SYMBOL_NAME: &str = "_SEGGER_RTT";

/// Parse ELF file and return the object::File for inspection
pub fn get_elf_file(elf_path: &Path) -> Result<File<'static>> {
    let elf_data = std::fs::read(elf_path).map_err(|e| {
        DebugError::RttError(format!("Failed to read ELF file {}: {}", elf_path.display(), e))
    })?;

    // Leak the data to create a static lifetime
    let elf_data_box = elf_data.into_boxed_slice();
    let elf_data_static: &'static [u8] = Box::leak(elf_data_box);

    object::File::parse(elf_data_static).map_err(|e| {
        DebugError::RttError(format!("Failed to parse ELF file {}: {}", elf_path.display(), e))
    })
}

/// Get symbol from ELF file by exact name match
pub fn get_symbol_from_elf(elf_path: &Path, symbol_name: &str) -> Result<SymbolInfo> {
    let file = get_elf_file(elf_path)?;

    for symbol in file.symbols() {
        let name = symbol.name().map_err(|_| DebugError::SymbolNotFound("invalid symbol name".to_string()))?;
        if name == symbol_name {
            return Ok(SymbolInfo {
                name: name.to_string(),
                address: symbol.address(),
                size: symbol.size(),
                section: get_symbol_section_name(&file, symbol),
            });
        }
    }

    Err(DebugError::SymbolNotFound(format!(
        "Symbol '{}' not found in ELF file {}",
        symbol_name,
        elf_path.display()
    )))
}

/// List all symbols in ELF that contain the given substring (case-insensitive)
pub fn find_symbols_by_pattern(elf_path: &Path, pattern: &str) -> Result<Vec<SymbolInfo>> {
    let file = get_elf_file(elf_path)?;
    let pattern_lower = pattern.to_lowercase();
    let mut results = Vec::new();

    for symbol in file.symbols() {
        if let Ok(name) = symbol.name() {
            if name.to_lowercase().contains(&pattern_lower) {
                results.push(SymbolInfo {
                    name: name.to_string(),
                    address: symbol.address(),
                    size: symbol.size(),
                    section: get_symbol_section_name(&file, symbol),
                });
            }
        }
    }

    if results.is_empty() {
        return Err(DebugError::SymbolNotFound(format!(
            "No symbols matching '{}' found in ELF file {}",
            pattern,
            elf_path.display()
        )));
    }

    Ok(results)
}

/// Get comprehensive ELF information for debugging
pub fn get_elf_debug_info(elf_path: &Path) -> Result<ElfDebugInfo> {
    let file = get_elf_file(elf_path)?;
    let mut debug_symbols = Vec::new();

    for symbol in file.symbols() {
        if let Ok(name) = symbol.name() {
            if name.contains("RTT") || name.contains("rtt") {
                debug_symbols.push(SymbolInfo {
                    name: name.to_string(),
                    address: symbol.address(),
                    size: symbol.size(),
                    section: get_symbol_section_name(&file, symbol),
                });
            }
        }
    }

    Ok(ElfDebugInfo {
        entry_point: file.entry(),
        symbol_count: file.symbols().count(),
        has_debug_info: file.sections().any(|s| s.name().map(|n| n.contains("debug")).unwrap_or(false)),
        rtt_related_symbols: debug_symbols,
    })
}

/// Extract RTT control block address from ELF symbol table
pub fn get_rtt_symbol_from_elf(elf_path: &Path) -> Result<u64> {
    debug!("Parsing ELF file for RTT symbol: {}", elf_path.display());

    let symbol_info = get_symbol_from_elf(elf_path, RTT_SYMBOL_NAME)?;

    let rtt_address = symbol_info.address;
    info!("Found {} symbol at address 0x{:08X}", RTT_SYMBOL_NAME, rtt_address);

    if is_valid_rtt_address(rtt_address) {
        Ok(rtt_address)
    } else {
        warn!("RTT symbol address 0x{:08X} appears invalid", rtt_address);
        Err(DebugError::RttError(format!(
            "RTT symbol found at invalid address 0x{:08X}",
            rtt_address
        )))
    }
}

/// Validate that RTT address is in a reasonable memory range
fn is_valid_rtt_address(address: u64) -> bool {
    const RAM_START: u64 = 0x20000000;
    const RAM_END: u64 = 0x2FFFFFFF;
    address >= RAM_START && address <= RAM_END
}

/// Get section name for a symbol
fn get_symbol_section_name(file: &File, symbol: object::Symbol) -> String {
    if let Some(section_index) = symbol.section_index() {
        for section in file.sections() {
            if section.index() == section_index {
                if let Ok(name) = section.name() {
                    return name.to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

#[derive(Debug)]
pub struct ElfDebugInfo {
    pub entry_point: u64,
    pub symbol_count: usize,
    pub has_debug_info: bool,
    pub rtt_related_symbols: Vec<SymbolInfo>,
}

#[derive(Debug)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub section: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_rtt_address() {
        assert!(is_valid_rtt_address(0x20000000));
        assert!(is_valid_rtt_address(0x20008000));
        assert!(is_valid_rtt_address(0x2000A000));
        assert!(!is_valid_rtt_address(0x08000000));
        assert!(!is_valid_rtt_address(0x00000000));
        assert!(!is_valid_rtt_address(0x40000000));
    }
}