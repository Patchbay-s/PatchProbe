# Trademarks

PatchProbe is a renamed continuation of IPScanner. The source code is free software, licensed under the
[GNU General Public License v3.0](LICENSE). The GPL grants you broad rights over the
**code**; it does not grant any rights over the project's **name and brand**.

## What is not covered by the GPL

- The former name **“IPScanner”** and its use to identify the original project and its builds.
- The name **“PatchProbe”** as used to identify this project and its official builds.
- The application icon, the logo and the visual identity of the project, including the
  files under `rust/app/src-tauri/icons/`, `rust/app/app-icon.png` and `.github/assets/`.
- The name and visual identity of the **Patchbay** app family.

## Forks and redistribution

You are welcome to fork, modify and redistribute the code under the terms of the GPL.
Before distributing a modified build (binary, installer, package, app store listing…), you
must:

1. **Rename** the application so it cannot be confused with PatchProbe or IPScanner.
2. **Replace the icon** and any other brand asset with your own.
3. **Change the application identifier** (`identifier` in
   `rust/app/src-tauri/tauri.conf.json`, currently `com.patchbay.patchprobe`) and the
   `productName`.

You may of course state factually that your project is *based on* or *a fork of*
PatchProbe.

Unmodified builds of an official release may be redistributed under their original name.

## Questions

If you are unsure whether your use is fine, open an issue before distributing.
