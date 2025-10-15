//! Color themes for terminal UI

use super::colors::*;

#[derive(Clone, Copy)]
pub enum Theme {
    Default,
    Dark,
    Light,
    Cyberpunk,
    Matrix,
}

impl Theme {
    pub fn primary(&self) -> &'static str {
        match self {
            Theme::Default => BRIGHT_CYAN,
            Theme::Dark => BRIGHT_BLUE,
            Theme::Light => BLUE,
            Theme::Cyberpunk => BRIGHT_MAGENTA,
            Theme::Matrix => BRIGHT_GREEN,
        }
    }

    pub fn secondary(&self) -> &'static str {
        match self {
            Theme::Default => BRIGHT_BLUE,
            Theme::Dark => CYAN,
            Theme::Light => CYAN,
            Theme::Cyberpunk => BRIGHT_CYAN,
            Theme::Matrix => GREEN,
        }
    }

    pub fn success(&self) -> &'static str {
        match self {
            Theme::Default | Theme::Dark | Theme::Light => BRIGHT_GREEN,
            Theme::Cyberpunk => BRIGHT_CYAN,
            Theme::Matrix => BRIGHT_GREEN,
        }
    }

    pub fn warning(&self) -> &'static str {
        BRIGHT_YELLOW
    }

    pub fn error(&self) -> &'static str {
        BRIGHT_RED
    }

    pub fn dim(&self) -> &'static str {
        DIM
    }
}
