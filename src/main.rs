//! Embedded Debugger MCP Server - Main Entry Point

use clap::Parser;
use tracing::{info, error, debug};
use tracing_subscriber::{EnvFilter, fmt};
use rmcp::{ServiceExt, transport::stdio};

use embedded_debugger_mcp::{
    Config,
    config::Args,
    tools::EmbeddedDebuggerToolHandler,
    debugger::registry::init_custom_registry,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = Args::parse();

    // Handle special flags first
    if args.generate_config {
        let config = Config::default();
        eprintln!("{}", config.to_toml()?);
        return Ok(());
    }

    // Initialize logging
    init_logging(&args)?;

    info!("Starting Debugger MCP Server v{}", env!("CARGO_PKG_VERSION"));
    debug!("Command line args: {:?}", args);

    // Load configuration
    let mut config = Config::load(args.config.as_ref())
        .map_err(|e| {
            error!("Failed to load configuration: {}", e);
            e
        })?;

    // Merge command line arguments into configuration
    config.merge_args(&args);

    if args.validate_config {
        config.validate()?;
        eprintln!("Configuration is valid");
        return Ok(());
    }

    if args.show_config {
        eprintln!("{}", config.to_toml()?);
        return Ok(());
    }

    // Validate final configuration
    config.validate()
        .map_err(|e| {
            error!("Configuration validation failed: {}", e);
            e
        })?;

    info!("Configuration loaded and validated successfully");

    // Initialize custom chip registry from 3rd-chip/*.yaml files
    // 相对路径时从 exe 目录查找，绝对路径直接使用
    let chip_dir = if config.debugger.chip_dir.is_relative() {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(&config.debugger.chip_dir)))
            .unwrap_or_else(|| config.debugger.chip_dir.clone())
    } else {
        config.debugger.chip_dir.clone()
    };
    if let Err(e) = init_custom_registry(&chip_dir).await {
        error!("Failed to initialize custom chip registry: {}", e);
    }

    // Create and serve the handler using rust-sdk standard pattern
    let service = EmbeddedDebuggerToolHandler::with_config(
        config.server.max_sessions,
        config.security.allow_flash_erase,
        config.security.restrict_memory_access,
        config.memory.max_read_size,
        config.memory.max_write_size,
        config.server.session_timeout_seconds,
    )
        .serve(stdio()).await.inspect_err(|e| {
            error!("Serving error: {:?}", e);
        })?;
    
    info!("Embedded Debugger MCP Server started successfully");
    
    // Wait for the service to complete
    service.waiting().await?;

    // Cleanup (simplified - no sessions to manage)
    info!("Cleaning up resources...");

    info!("Embedded Debugger MCP Server stopped");
    Ok(())
}

/// Initialize logging system
fn init_logging(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    // Determine log file path (use exe directory for default path)
    let log_file_path = if args.enable_file_log {
        Some(args.log_file.clone().unwrap_or_else(|| {
            // 默认日志路径：exe所在目录/mcp-server.log
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("mcp-server.log")))
                .unwrap_or_else(|| std::path::PathBuf::from("mcp-server.log"))
        }))
    } else {
        args.log_file.clone()
    };

    // Configure output destination
    if let Some(log_file) = &log_file_path {
        // Ensure parent directory exists
        if let Some(parent) = log_file.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;

        // File 需要 Mutex 包装才能正确实现 MakeWriter trait
        let file_writer = std::sync::Mutex::new(file);

        fmt::Subscriber::builder()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(true)
            .with_file(false)
            .with_line_number(false)
            .with_writer(file_writer)
            .with_ansi(false)
            .init();

        eprintln!("Logging to file: {}", log_file.display());
    } else {
        // 默认输出到 stderr，绝不能输出到 stdout（MCP协议通道）
        fmt::Subscriber::builder()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(true)
            .with_file(false)
            .with_line_number(false)
            .with_writer(std::io::stderr)
            .init();
    }

    debug!("Logging initialized with level: {}", args.log_level);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from(&[
            "debugger-mcp-rs",
            "--log-level", "debug",
            "--max-sessions", "10",
        ]);
        
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.max_sessions, 10);
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.server.max_sessions, 5);
        assert_eq!(config.debugger.default_speed_khz, 4000);
    }

}