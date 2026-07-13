//! Flash programming manager - Real probe-rs integration

use crate::error::{Result, DebugError};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};

// Probe-rs imports  
use probe_rs::{flashing::{self, FlashProgress}, Session, MemoryInterface};

/// Erase operation types
#[derive(Debug, Clone)]
pub enum EraseType {
    /// Erase entire flash
    All,
    /// Erase specific sectors
    Sectors { address: u64, size: usize },
}

/// File format types
#[derive(Debug, Clone)]
pub enum FileFormat {
    Auto,
    Elf,
    Hex,
    Bin,
}

/// Erase operation result
#[derive(Debug)]
pub struct EraseResult {
    pub erase_time_ms: u64,
    pub sectors_erased: Option<usize>,
}

/// Programming operation result
#[derive(Debug)]
pub struct ProgramResult {
    pub bytes_programmed: usize,
    pub programming_time_ms: u64,
    pub verification_result: Option<bool>,
}

/// Verification result
#[derive(Debug)]
pub struct VerifyResult {
    pub success: bool,
    pub bytes_verified: usize,
    pub mismatches: Vec<VerifyMismatch>,
}

/// Verification mismatch
#[derive(Debug)]
pub struct VerifyMismatch {
    pub address: u64,
    pub expected: u8,
    pub actual: u8,
}

/// Flash manager for programming operations
pub struct FlashManager;

impl FlashManager {
    /// Create a new flash manager
    pub fn new() -> Self {
        Self
    }

    /// Erase flash memory
    pub async fn erase_flash(
        session: &mut Session,
        erase_type: EraseType,
    ) -> Result<EraseResult> {
        let start_time = Instant::now();
        
        match erase_type {
            EraseType::All => {
                debug!("Starting full flash erase");
                flashing::erase_all(session, &mut FlashProgress::empty(), false)
                    .map_err(|e| DebugError::FlashOperationFailed(format!("Full erase failed: {}", e)))?;
                
                info!("Full flash erase completed");
                Ok(EraseResult {
                    erase_time_ms: start_time.elapsed().as_millis() as u64,
                    sectors_erased: None,
                })
            }
            EraseType::Sectors { address, size } => {
                debug!("Starting sector erase at 0x{:08X}, size: {} bytes", address, size);

                // Use FlashLoader to properly erase flash sectors via flash algorithms.
                // Adding 0xFF data triggers the FlashLoader to erase the affected sectors.
                let mut loader = session.target().flash_loader();
                let erase_data = vec![0xFFu8; size];
                loader.add_data(address, &erase_data)
                    .map_err(|e| DebugError::FlashOperationFailed(format!("Failed to stage erase data: {}", e)))?;

                let mut options = flashing::DownloadOptions::default();
                options.verify = false;
                options.progress = FlashProgress::empty();
                loader.commit(session, options)
                    .map_err(|e| DebugError::FlashOperationFailed(format!("Sector erase failed: {}", e)))?;

                // Estimate sector count (target-specific, using common 2KB sector size)
                let sector_size = 2048;
                let sector_count = size.div_ceil(sector_size);

                info!("Sector erase completed: {} sectors", sector_count);
                Ok(EraseResult {
                    erase_time_ms: start_time.elapsed().as_millis() as u64,
                    sectors_erased: Some(sector_count),
                })
            }
        }
    }

    /// Program file to flash
    ///
    /// # Arguments
    /// * `verify` - Whether to verify flash contents after programming
    pub async fn program_file(
        session: &mut Session,
        file_path: &Path,
        format: FileFormat,
        base_address: Option<u64>,
        verify: bool,
    ) -> Result<ProgramResult> {
        let start_time = Instant::now();
        
        // Check file existence
        if !file_path.exists() {
            return Err(DebugError::FlashOperationFailed(format!("File not found: {}", file_path.display())));
        }

        debug!("Programming file: {}", file_path.display());

        // Determine format
        let probe_format = match format {
            FileFormat::Auto => {
                // Auto-detect based on extension
                match file_path.extension().and_then(|s| s.to_str()) {
                    Some("elf") => flashing::Format::Elf(flashing::ElfOptions::default()),
                    Some("hex") => flashing::Format::Hex,
                    Some("bin") => flashing::Format::Bin(flashing::BinOptions { base_address: None, skip: 0 }),
                    _ => return Err(DebugError::FlashOperationFailed("Cannot auto-detect file format".to_string())),
                }
            }
            FileFormat::Elf => flashing::Format::Elf(flashing::ElfOptions::default()),
            FileFormat::Hex => flashing::Format::Hex,
            FileFormat::Bin => flashing::Format::Bin(flashing::BinOptions { base_address, skip: 0 }),
        };

        // Setup download options - respect verify parameter
        let mut options = flashing::DownloadOptions::default();
        options.verify = verify;
        options.progress = FlashProgress::empty();

        // Set base address for BIN files - this might need to be handled differently
        if matches!(probe_format, flashing::Format::Bin(_)) {
            if let Some(addr) = base_address {
                // Note: probe-rs API may need different approach for base address
                warn!("Base address specification for BIN files: 0x{:08X} - may require different API usage", addr);
            }
        }

        // Execute programming
        flashing::download_file_with_options(session, file_path, probe_format, options)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Programming failed: {}", e)))?;

        let elapsed = start_time.elapsed().as_millis() as u64;
        
        info!("File programming completed in {}ms", elapsed);
        
        // Since we can't get exact bytes from probe-rs API, estimate from file size
        let file_size = std::fs::metadata(file_path)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        
        Ok(ProgramResult {
            bytes_programmed: file_size,
            programming_time_ms: elapsed,
            verification_result: if verify { Some(true) } else { None },
        })
    }

    /// Program binary data to flash
    pub async fn program_data(
        session: &mut Session,
        data: &[u8],
        base_address: u64,
    ) -> Result<ProgramResult> {
        let start_time = Instant::now();
        
        debug!("Programming {} bytes to address 0x{:08X}", data.len(), base_address);

        // Use FlashLoader for proper flash programming via flash algorithms
        let mut loader = session.target().flash_loader();
        loader.add_data(base_address, data)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Failed to stage data: {}", e)))?;

        let mut options = flashing::DownloadOptions::default();
        options.verify = false;
        options.progress = FlashProgress::empty();
        loader.commit(session, options)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Failed to program data: {}", e)))?;

        let elapsed = start_time.elapsed().as_millis() as u64;

        info!("Data programming completed: {} bytes in {}ms", data.len(), elapsed);

        Ok(ProgramResult {
            bytes_programmed: data.len(),
            programming_time_ms: elapsed,
            verification_result: None, // Manual verification needed
        })
    }

    /// Verify flash contents
    pub async fn verify_flash(
        session: &mut Session,
        expected_data: &[u8],
        address: u64,
    ) -> Result<VerifyResult> {
        debug!("Verifying {} bytes at address 0x{:08X}", expected_data.len(), address);

        let mut core = session.core(0)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Failed to get core: {}", e)))?;
        
        // Read actual data from flash
        let mut actual_data = vec![0u8; expected_data.len()];
        core.read(address, &mut actual_data)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Failed to read flash: {}", e)))?;

        // Compare data and find mismatches
        let mut mismatches = Vec::new();
        for (i, (expected, actual)) in expected_data.iter().zip(actual_data.iter()).enumerate() {
            if expected != actual {
                mismatches.push(VerifyMismatch {
                    address: address + i as u64,
                    expected: *expected,
                    actual: *actual,
                });
            }
        }

        let success = mismatches.is_empty();
        
        if success {
            info!("Flash verification successful: {} bytes", expected_data.len());
        } else {
            warn!("Flash verification failed: {} mismatches", mismatches.len());
        }

        Ok(VerifyResult {
            success,
            bytes_verified: expected_data.len(),
            mismatches,
        })
    }
}

impl Default for FlashManager {
    fn default() -> Self {
        Self::new()
    }
}