//! User interaction helpers for ByteLock.
//!
//! This module centralizes all terminal I/O, prompting, and clipboard
//! interactions. No cryptographic or vault logic should live here.

use std::io::{self, Write};
use std::time::Duration;
use clipboard::{ClipboardContext, ClipboardProvider};

pub fn prompt_yes(prompt: &str) -> bool {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    matches!(s.trim().to_lowercase().as_str(), "y" | "yes")
}

pub fn copy_to_clipboard_with_timeout(text: &str, secs: u64) -> Result<(), String> {
    let mut ctx: ClipboardContext = ClipboardProvider::new()
        .map_err(|e| format!("Clipboard init error: {}", e))?;

    ctx.set_contents(text.to_string())
        .map_err(|e| format!("Clipboard set error: {}", e))?;

    let text = text.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));

        let ctx2_result: Result<ClipboardContext, _> = ClipboardProvider::new();
        if let Ok(mut ctx2) = ctx2_result {
            let current_result: Result<String, _> = ctx2.get_contents();
            if current_result.ok().as_deref() == Some(&text) {
                let _ = ctx2.set_contents(String::new());
            }
        }
    });

    Ok(())
}
