//! # Terminal UI Module
//!
//! Modern terminal user interface for AVO Protocol Node

use std::io::{self, Write};
use std::time::Duration;
use tokio::time;

pub mod banner;
pub mod dashboard;
pub mod theme;

pub use banner::print_startup_banner;
pub use dashboard::NodeDashboard;
pub use theme::Theme;

/// ANSI color codes
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";

    // Colors
    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";

    // Bright colors
    pub const BRIGHT_BLACK: &str = "\x1b[90m";
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const BRIGHT_WHITE: &str = "\x1b[97m";

    // Background
    pub const BG_BLACK: &str = "\x1b[40m";
    pub const BG_RED: &str = "\x1b[41m";
    pub const BG_GREEN: &str = "\x1b[42m";
    pub const BG_YELLOW: &str = "\x1b[43m";
    pub const BG_BLUE: &str = "\x1b[44m";
}

/// Clear screen
pub fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    io::stdout().flush().unwrap();
}

/// Move cursor to position
pub fn move_cursor(x: u16, y: u16) {
    print!("\x1b[{};{}H", y, x);
}

/// Hide cursor
pub fn hide_cursor() {
    print!("\x1b[?25l");
    io::stdout().flush().unwrap();
}

/// Show cursor
pub fn show_cursor() {
    print!("\x1b[?25h");
    io::stdout().flush().unwrap();
}

/// Print with color
pub fn print_colored(text: &str, color: &str) {
    print!("{}{}{}", color, text, colors::RESET);
}

/// Print with color and newline
pub fn println_colored(text: &str, color: &str) {
    println!("{}{}{}", color, text, colors::RESET);
}

/// Progress bar
pub fn progress_bar(current: usize, total: usize, width: usize) -> String {
    let percentage = (current as f64 / total as f64 * 100.0) as usize;
    let filled = (current as f64 / total as f64 * width as f64) as usize;
    let empty = width - filled;

    format!(
        "[{}{}{}{}] {}%",
        colors::GREEN,
        "█".repeat(filled),
        colors::DIM,
        "░".repeat(empty),
        percentage
    )
}

/// Spinner animation
pub struct Spinner {
    frames: Vec<&'static str>,
    current: usize,
}

impl Spinner {
    pub fn new() -> Self {
        Self {
            frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current: 0,
        }
    }

    pub fn next(&mut self) -> &str {
        let frame = self.frames[self.current];
        self.current = (self.current + 1) % self.frames.len();
        frame
    }
}

/// Box drawing characters
pub mod box_chars {
    // Single line
    pub const HORIZONTAL: char = '─';
    pub const VERTICAL: char = '│';
    pub const TOP_LEFT: char = '┌';
    pub const TOP_RIGHT: char = '┐';
    pub const BOTTOM_LEFT: char = '└';
    pub const BOTTOM_RIGHT: char = '┘';
    pub const CROSS: char = '┼';
    pub const T_LEFT: char = '├';
    pub const T_RIGHT: char = '┤';
    pub const T_TOP: char = '┬';
    pub const T_BOTTOM: char = '┴';

    // Double line
    pub const DOUBLE_HORIZONTAL: char = '═';
    pub const DOUBLE_VERTICAL: char = '║';
    pub const DOUBLE_TOP_LEFT: char = '╔';
    pub const DOUBLE_TOP_RIGHT: char = '╗';
    pub const DOUBLE_BOTTOM_LEFT: char = '╚';
    pub const DOUBLE_BOTTOM_RIGHT: char = '╝';
}

/// Draw a box
pub fn draw_box(x: u16, y: u16, width: u16, height: u16, title: Option<&str>) {
    // Top border
    move_cursor(x, y);
    print!("{}", box_chars::TOP_LEFT);
    if let Some(t) = title {
        let title_str = format!(" {} ", t);
        let padding = (width as usize - 2 - title_str.len()) / 2;
        print!("{}", box_chars::HORIZONTAL.to_string().repeat(padding));
        print_colored(&title_str, colors::BRIGHT_CYAN);
        print!("{}", box_chars::HORIZONTAL.to_string().repeat(width as usize - 2 - padding - title_str.len()));
    } else {
        print!("{}", box_chars::HORIZONTAL.to_string().repeat(width as usize - 2));
    }
    print!("{}", box_chars::TOP_RIGHT);

    // Sides
    for i in 1..height - 1 {
        move_cursor(x, y + i);
        print!("{}", box_chars::VERTICAL);
        move_cursor(x + width - 1, y + i);
        print!("{}", box_chars::VERTICAL);
    }

    // Bottom border
    move_cursor(x, y + height - 1);
    print!("{}", box_chars::BOTTOM_LEFT);
    print!("{}", box_chars::HORIZONTAL.to_string().repeat(width as usize - 2));
    print!("{}", box_chars::BOTTOM_RIGHT);

    io::stdout().flush().unwrap();
}
