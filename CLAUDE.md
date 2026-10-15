# Project guidelines

- Keep the public product name PatchProbe and the Rust/Tauri implementation.
- Use RFC 5737 addresses and locally administered `02:00:00` MAC addresses in
  fixtures. Never commit results captured from a real network.
- Keep signing and updater credentials in environment variables or repository
  secrets; never commit local environment files or signing material.
- Run `cargo fmt --check`, workspace Clippy and tests, and the frontend build
  before submitting changes.
