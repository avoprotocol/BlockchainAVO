//! Real-time node dashboard

use super::colors::*;
use super::{box_chars, draw_box, move_cursor, progress_bar};
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

pub struct NodeDashboard {
    pub block_height: u64,
    pub finalized_height: u64,
    pub peer_count: usize,
    pub tps: f64,
    pub memory_mb: usize,
    pub cpu_percent: f32,
    pub uptime_secs: u64,
    pub is_validator: bool,
    pub is_syncing: bool,
    pub latest_block_time: Option<SystemTime>,
}

impl NodeDashboard {
    pub fn new(is_validator: bool) -> Self {
        Self {
            block_height: 0,
            finalized_height: 0,
            peer_count: 0,
            tps: 0.0,
            memory_mb: 0,
            cpu_percent: 0.0,
            uptime_secs: 0,
            is_validator,
            is_syncing: true,
            latest_block_time: None,
        }
    }

    pub fn render(&self) {
        // Move to dashboard area (below banner)
        move_cursor(1, 25);

        // Header
        println!("{}{}═══════════════════════════════════════════════════════════════{}",
            BOLD, BRIGHT_CYAN, RESET);
        println!("{}{}                      LIVE NODE DASHBOARD                      {}",
            BOLD, BRIGHT_CYAN, RESET);
        println!("{}{}═══════════════════════════════════════════════════════════════{}",
            BOLD, BRIGHT_CYAN, RESET);
        println!();

        // Top section: Chain Status and Network
        self.render_chain_status();
        println!();
        self.render_network_status();
        println!();

        // Middle section: Performance
        self.render_performance();
        println!();

        // Bottom section: Recent Activity
        self.render_recent_activity();

        io::stdout().flush().unwrap();
    }

    fn render_chain_status(&self) {
        println!("  {}┌──────────────────────── CHAIN STATUS ────────────────────────┐{}", BRIGHT_BLUE, RESET);

        // Block height
        let sync_status = if self.is_syncing {
            format!("{}SYNCING{}", BRIGHT_YELLOW, RESET)
        } else {
            format!("{}SYNCED{}", BRIGHT_GREEN, RESET)
        };

        println!("  {}│{}  Block Height:     {}{:>10}{}  {}Status: {}          {}│{}",
            BRIGHT_BLUE, RESET, BRIGHT_WHITE, self.block_height, RESET,
            BRIGHT_BLACK, sync_status,
            " ".repeat(7), BRIGHT_BLUE, RESET);

        // Finalized height
        let finality_lag = self.block_height.saturating_sub(self.finalized_height);
        let lag_color = if finality_lag < 10 {
            BRIGHT_GREEN
        } else if finality_lag < 50 {
            BRIGHT_YELLOW
        } else {
            BRIGHT_RED
        };

        println!("  {}│{}  Finalized:       {}{:>10}{}  {}Lag: {}{:>3} blocks{}    {}│{}",
            BRIGHT_BLUE, RESET, BRIGHT_WHITE, self.finalized_height, RESET,
            BRIGHT_BLACK, lag_color, finality_lag, RESET,
            BRIGHT_BLUE, RESET);

        // Validator status
        if self.is_validator {
            println!("  {}│{}  Validator:       {}{}ACTIVE ✓{}                        {}│{}",
                BRIGHT_BLUE, RESET, BOLD, BRIGHT_GREEN, RESET,
                " ".repeat(8), BRIGHT_BLUE, RESET);
        } else {
            println!("  {}│{}  Mode:            {}Full Node{}                         {}│{}",
                BRIGHT_BLUE, RESET, BRIGHT_WHITE, RESET,
                " ".repeat(8), BRIGHT_BLUE, RESET);
        }

        println!("  {}└───────────────────────────────────────────────────────────────┘{}", BRIGHT_BLUE, RESET);
    }

    fn render_network_status(&self) {
        println!("  {}┌─────────────────────── NETWORK STATUS ───────────────────────┐{}", BRIGHT_BLUE, RESET);

        // Peer count
        let peer_color = if self.peer_count >= 8 {
            BRIGHT_GREEN
        } else if self.peer_count >= 4 {
            BRIGHT_YELLOW
        } else {
            BRIGHT_RED
        };

        println!("  {}│{}  Connected Peers:  {}{:>3}{}  {}{}                          {}│{}",
            BRIGHT_BLUE, RESET, peer_color, self.peer_count, RESET,
            self.get_peer_bar(self.peer_count),
            " ".repeat(15), BRIGHT_BLUE, RESET);

        // Network health
        let health = if self.peer_count >= 8 && !self.is_syncing {
            format!("{}EXCELLENT{}", BRIGHT_GREEN, RESET)
        } else if self.peer_count >= 4 {
            format!("{}GOOD{}", BRIGHT_YELLOW, RESET)
        } else {
            format!("{}POOR{}", BRIGHT_RED, RESET)
        };

        println!("  {}│{}  Network Health:  {}                                  {}│{}",
            BRIGHT_BLUE, RESET, health,
            " ".repeat(23), BRIGHT_BLUE, RESET);

        // Uptime
        let uptime_str = self.format_uptime(self.uptime_secs);
        println!("  {}│{}  Uptime:          {}{}{}                          {}│{}",
            BRIGHT_BLUE, RESET, BRIGHT_WHITE, uptime_str, RESET,
            " ".repeat(32 - uptime_str.len()), BRIGHT_BLUE, RESET);

        println!("  {}└───────────────────────────────────────────────────────────────┘{}", BRIGHT_BLUE, RESET);
    }

    fn render_performance(&self) {
        println!("  {}┌───────────────────── PERFORMANCE METRICS ────────────────────┐{}", BRIGHT_BLUE, RESET);

        // TPS
        let tps_color = if self.tps > 1000.0 {
            BRIGHT_GREEN
        } else if self.tps > 100.0 {
            BRIGHT_YELLOW
        } else {
            BRIGHT_WHITE
        };

        println!("  {}│{}  Transactions/sec: {}{:>8.1}{} TPS                         {}│{}",
            BRIGHT_BLUE, RESET, tps_color, self.tps, RESET,
            " ".repeat(6), BRIGHT_BLUE, RESET);

        // CPU
        let cpu_bar = progress_bar(self.cpu_percent as usize, 100, 20);
        println!("  {}│{}  CPU Usage:       {}{}                         {}│{}",
            BRIGHT_BLUE, RESET, cpu_bar,
            " ".repeat(10), BRIGHT_BLUE, RESET);

        // Memory
        let mem_bar = progress_bar((self.memory_mb / 10).min(100), 100, 20);
        println!("  {}│{}  Memory:          {}{} {}{:>5} MB{}             {}│{}",
            BRIGHT_BLUE, RESET, mem_bar, RESET, BRIGHT_WHITE, self.memory_mb, RESET,
            " ".repeat(3), BRIGHT_BLUE, RESET);

        println!("  {}└───────────────────────────────────────────────────────────────┘{}", BRIGHT_BLUE, RESET);
    }

    fn render_recent_activity(&self) {
        println!("  {}┌──────────────────── RECENT ACTIVITY ─────────────────────────┐{}", BRIGHT_BLUE, RESET);

        if let Some(block_time) = self.latest_block_time {
            let elapsed = SystemTime::now()
                .duration_since(block_time)
                .unwrap_or(Duration::from_secs(0));

            println!("  {}│{}  {}●{} Latest block received {}{}s ago{}                   {}│{}",
                BRIGHT_BLUE, RESET, BRIGHT_GREEN, RESET,
                BRIGHT_WHITE, elapsed.as_secs(), RESET,
                " ".repeat(15 - elapsed.as_secs().to_string().len()),
                BRIGHT_BLUE, RESET);
        } else {
            println!("  {}│{}  {}○{} Waiting for first block...{}                       {}│{}",
                BRIGHT_BLUE, RESET, BRIGHT_BLACK, RESET,
                " ".repeat(18),
                BRIGHT_BLUE, RESET);
        }

        if self.is_validator {
            println!("  {}│{}  {}●{} Validator duties: Active{}                         {}│{}",
                BRIGHT_BLUE, RESET, BRIGHT_GREEN, RESET,
                " ".repeat(16),
                BRIGHT_BLUE, RESET);
        }

        println!("  {}│{}  {}●{} P2P connections: Stable{}                           {}│{}",
            BRIGHT_BLUE, RESET, BRIGHT_GREEN, RESET,
            " ".repeat(16),
            BRIGHT_BLUE, RESET);

        println!("  {}└───────────────────────────────────────────────────────────────┘{}", BRIGHT_BLUE, RESET);
    }

    fn get_peer_bar(&self, peer_count: usize) -> String {
        let max_peers = 20;
        let filled = (peer_count.min(max_peers) as f64 / max_peers as f64 * 10.0) as usize;
        let color = if peer_count >= 8 {
            BRIGHT_GREEN
        } else if peer_count >= 4 {
            BRIGHT_YELLOW
        } else {
            BRIGHT_RED
        };

        format!("{}[{}{}]{}",
            color,
            "█".repeat(filled),
            "░".repeat(10 - filled),
            RESET
        )
    }

    fn format_uptime(&self, secs: u64) -> String {
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;

        if hours > 0 {
            format!("{}h {:02}m {:02}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {:02}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }
}

pub fn print_log_message(level: &str, component: &str, message: &str) {
    let (level_color, level_icon) = match level.to_lowercase().as_str() {
        "error" => (BRIGHT_RED, "✗"),
        "warn" => (BRIGHT_YELLOW, "⚠"),
        "info" => (BRIGHT_BLUE, "ℹ"),
        "debug" => (BRIGHT_BLACK, "⚙"),
        "trace" => (DIM, "·"),
        _ => (RESET, "•"),
    };

    let timestamp = chrono::Local::now().format("%H:%M:%S");

    println!("{}[{}]{} {}{}{} {}{:<12}{} {}",
        BRIGHT_BLACK, timestamp, RESET,
        level_color, level_icon, RESET,
        BRIGHT_CYAN, component, RESET,
        message
    );
}
