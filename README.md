# ByteLock

**ByteLock** is a small, secure, and simple command-line password manager written in Rust. It uses modern cryptography (Argon2id + XChaCha20Poly1305) to safely store passwords in a local vault. The tool allows password generation, storage, retrieval, and temporary clipboard copy.

---

## Features

* **Secure Vault**: All passwords are encrypted with a master password.
* **Argon2id Key Derivation**: Configurable memory, iterations, and parallelism for strong key derivation.
* **XChaCha20Poly1305 Encryption**: Modern authenticated encryption for password storage.
* **Password Generation**: Generate strong passwords with customizable options.
* **Clipboard Copy with Timeout**: Temporarily copy passwords to the clipboard for 10 seconds.
* **Master Password Management**: Change the master password with automatic re-encryption of entries.
* **Zeroization**: Sensitive data is cleared from memory when no longer needed.

---

## Installation

You need Rust installed. Then clone and build the project:

```bash
git clone https://github.com/mesametamaarkhan/bytelock.git
cd bytelock
cargo build --release
```

---

## Usage

Run the CLI tool:

```bash
cargo run -- <command> [options]
```

### Commands

* **init**
  Initialize a new vault.

* **add `<name>` [--force]**
  Add a new entry (password will be prompted). Use `--force` to overwrite existing entries.

* **get `<name>` [--copy]**
  Retrieve a stored password. Use `--copy` to temporarily copy to clipboard.

* **list**
  List all entries in the vault.

* **remove `<name>`**
  Remove an entry.

* **update `<name>`**
  Update an existing entry.

* **passwd**
  Change the master password (re-encrypts all entries).

* **gen [options]**
  Generate a password. Options:

  * `-l`, `--length` → Password length (default 16)
  * `--no-uppercase` → Exclude uppercase
  * `--no-lowercase` → Exclude lowercase
  * `--no-digits` → Exclude digits
  * `--no-symbols` → Exclude symbols
  * `--exclude-ambiguous` → Exclude ambiguous characters (`Il1O0`)

---

## Example

```bash
# Initialize vault
cargo run -- init

# Add a new entry
cargo run -- add github

# Get password and copy to clipboard
cargo run -- get github --copy

# Generate a strong password
cargo run -- gen -l 24
```

---

## Security Notes

* Master password and plaintext passwords are zeroized in memory.
* The clipboard is cleared automatically after 10 seconds.
* Vault is stored locally as `vault.json`. Make backups before modifying passwords.

---

## Dependencies

* Rust 1.70+
* `argon2` for password-based key derivation
* `chacha20poly1305` for encryption
* `serde` and `serde_json` for vault serialization
* `clap` for CLI parsing
* `clipboard` for clipboard support
* `rpassword` for hidden password prompts

> **Linux users:** You may need development libraries for clipboard support, e.g., `libx11-dev`, `libx11-xcb-dev`, `libxcb-render0-dev`, `libxcb-shape0-dev`, `libxcb-xfixes0-dev`.

---

## Project Structure

```
src/
├─ main.rs        # CLI and command handling
├─ crypto.rs      # Encryption and key derivation
└─ vault.rs       # Vault structure, persistence, and master password management
```

---

## License

MIT License © 2025 [Your Name]

---

## Contributing

Contributions are welcome! Please submit issues or pull requests. Focus areas:

* Cross-platform clipboard support
* Testing and validation
* Additional vault features (import/export, profiles)
* UI/UX improvements
