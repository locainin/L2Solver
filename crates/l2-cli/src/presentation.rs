//! Shared text presentation for wired and wireless assessments

use l2_cli::arguments::ColorChoice;
use std::io::{self, Write};

#[derive(Clone, Copy)]
pub struct Presentation {
    color: bool,
}

impl Presentation {
    #[must_use]
    pub const fn new(color: ColorChoice) -> Self {
        Self {
            color: matches!(color, ColorChoice::Always),
        }
    }

    pub fn title(self, title: &str, output: &mut impl Write) -> io::Result<()> {
        if self.color {
            writeln!(output, "\x1b[1m{title}\x1b[0m")
        } else {
            writeln!(output, "{title}")
        }
    }

    pub fn section(self, title: &str, output: &mut impl Write) -> io::Result<()> {
        if self.color {
            writeln!(output, "\n\x1b[1;36m{title}\x1b[0m")
        } else {
            writeln!(output, "\n{title}")
        }
    }
}
