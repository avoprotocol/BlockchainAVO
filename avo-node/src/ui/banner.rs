//! Startup banner and logo

use super::colors::*;
use super::println_colored;

pub fn print_startup_banner() {
    println!();
    println_colored(&format!("{}{}",BRIGHT_GREEN, r#"
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║       █████╗ ██╗   ██╗ ██████╗     ██████╗ ██████╗  ██████╗  ║
    ║      ██╔══██╗██║   ██║██╔═══██╗    ██╔══██╗██╔══██╗██╔═══██╗ ║
    ║      ███████║██║   ██║██║   ██║    ██████╔╝██████╔╝██║   ██║ ║
    ║      ██╔══██║╚██╗ ██╔╝██║   ██║    ██╔═══╝ ██╔══██╗██║   ██║ ║
    ║      ██║  ██║ ╚████╔╝ ╚██████╔╝    ██║     ██║  ██║╚██████╔╝ ║
    ║      ╚═╝  ╚═╝  ╚═══╝   ╚═════╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    "#), RESET);

    println!();
    println_colored(&format!("{}                Next-Generation Layer 1 Blockchain", BRIGHT_CYAN), RESET);
    println_colored(&format!("{}                Version 1.0.0 • Production Ready", DIM), RESET);
    println!();
}

pub fn print_startup_info(node_type: &str, is_validator: bool) {
    println_colored(&format!("    {}┌─────────────────────────────────────────────────────────────┐", BRIGHT_BLUE), RESET);
    println_colored(&format!("    {}│  {}Node Type:{}     {}{}                                  ",
        BRIGHT_BLUE, BOLD, RESET, BRIGHT_YELLOW, node_type), RESET);
    println_colored(&format!("    {}│  {}Mode:{}         {}{}                                  ",
        BRIGHT_BLUE, BOLD, RESET,
        if is_validator { BRIGHT_GREEN } else { BRIGHT_WHITE },
        if is_validator { "Validator ✓" } else { "Full Node" }), RESET);
    println_colored(&format!("    {}│  {}Consensus:{}    {}Flow (DAG) + 2PC                      ",
        BRIGHT_BLUE, BOLD, RESET, BRIGHT_CYAN), RESET);
    println_colored(&format!("    {}│  {}Sharding:{}     {}Dynamic (2-64 shards)                 ",
        BRIGHT_BLUE, BOLD, RESET, BRIGHT_CYAN), RESET);
    println_colored(&format!("    {}└─────────────────────────────────────────────────────────────┘", BRIGHT_BLUE), RESET);
    println!();
}

pub fn print_loading_phase(phase: &str, status: &str) {
    println_colored(&format!("    {}▸ {}{:<30}{} {}{}",
        BRIGHT_BLUE, RESET, phase, BRIGHT_BLACK, status, RESET), RESET);
}

pub fn print_success_phase(phase: &str) {
    println_colored(&format!("    {}✓ {}{:<30}{} {}",
        BRIGHT_GREEN, RESET, phase, BRIGHT_GREEN, "OK"), RESET);
}

pub fn print_error_phase(phase: &str, error: &str) {
    println_colored(&format!("    {}✗ {}{:<30}{} {}",
        BRIGHT_RED, RESET, phase, BRIGHT_RED, error), RESET);
}

pub fn print_separator() {
    println_colored(&format!("    {}{}",
        BRIGHT_BLACK, "─".repeat(63)), RESET);
}

pub fn print_node_ready(ws_port: u16, rpc_port: u16, p2p_port: u16) {
    println!();
    println_colored(&format!("    {}╔═══════════════════════════════════════════════════════════════╗", BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║  {}🚀  NODE ONLINE AND READY                                   {}║",
        BRIGHT_GREEN, BOLD, RESET), RESET);
    println_colored(&format!("    {}╠═══════════════════════════════════════════════════════════════╣", BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║                                                               ║", BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║  {}Endpoints:{}                                                  {}║",
        BRIGHT_GREEN, BOLD, RESET, BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║    {}WebSocket:{}  {}ws://127.0.0.1:{}{}                        {}║",
        BRIGHT_GREEN, BRIGHT_CYAN, RESET, BRIGHT_WHITE, ws_port,
        " ".repeat(63 - 37 - ws_port.to_string().len()), BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║    {}HTTP RPC:{}   {}http://127.0.0.1:{}{}                      {}║",
        BRIGHT_GREEN, BRIGHT_CYAN, RESET, BRIGHT_WHITE, rpc_port,
        " ".repeat(63 - 39 - rpc_port.to_string().len()), BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║    {}P2P Port:{}   {}:{}{}                                      {}║",
        BRIGHT_GREEN, BRIGHT_CYAN, RESET, BRIGHT_WHITE, p2p_port,
        " ".repeat(63 - 39 - p2p_port.to_string().len()), BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║                                                               ║", BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║  {}Controls:{}                                                   {}║",
        BRIGHT_GREEN, BOLD, RESET, BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║    {}Ctrl+C{}     → Graceful shutdown                           {}║",
        BRIGHT_GREEN, BRIGHT_YELLOW, RESET, BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║    {}Ctrl+D{}     → Force quit                                  {}║",
        BRIGHT_GREEN, BRIGHT_YELLOW, RESET, BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}║                                                               ║", BRIGHT_GREEN), RESET);
    println_colored(&format!("    {}╚═══════════════════════════════════════════════════════════════╝", BRIGHT_GREEN), RESET);
    println!();
}

pub fn print_shutdown_banner() {
    println!();
    println_colored(&format!("    {}┌─────────────────────────────────────────────────────────────┐", BRIGHT_YELLOW), RESET);
    println_colored(&format!("    {}│  {}⏹  SHUTDOWN SEQUENCE INITIATED                            {}│",
        BRIGHT_YELLOW, BOLD, RESET), RESET);
    println_colored(&format!("    {}└─────────────────────────────────────────────────────────────┘", BRIGHT_YELLOW), RESET);
    println!();
}
