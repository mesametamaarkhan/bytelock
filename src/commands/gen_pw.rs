//! Generate a random password.

use crate::ui;

pub fn run(
    length: usize,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
    copy: bool,
) {
    let pwd = crate::auth::generate_password(
        length,
        use_upper,
        use_lower,
        use_digits,
        use_symbols,
        exclude_ambiguous,
    );

    println!("{}", pwd);

    if copy {
        if let Err(e) = ui::copy_to_clipboard_with_timeout(&pwd, 10) {
            println!("Failed to copy to clipboard: {}", e);
        }
    }
}
