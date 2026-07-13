//! Embedded debugger MCP tools module
//! 
//! This module provides a unified tool handler for all embedded debugging operations
//! using the RMCP 1.7 API patterns, similar to the serial-mcp-rs implementation.

// Module declarations
pub mod debugger_tools;
pub mod types;

// Export all 24 tools (18 base debugging + 6 RTT communication)
pub use debugger_tools::*;
pub use types::*;