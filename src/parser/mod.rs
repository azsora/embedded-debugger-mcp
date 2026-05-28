//! Parser module - ELF and DWARF parsing utilities
//!
//! Provides low-level parsing capabilities for ELF symbol tables and DWARF debug information.

pub mod dwarf_parser;
pub use dwarf_parser::*;