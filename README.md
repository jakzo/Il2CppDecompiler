Ghidra extension for decompiling code from a Unity IL2CPP game to C#.

> ℹ️ The extension is not ready to use yet but there is a [hacky script](ghidra_scripts/DecompileToCSharp.java) you can currently run in Ghidra which will clean up the Ghidra decompiled C code significantly.

## Usage

1. Create/modify [gradle.properties](gradle.properties) to contain:
   ```env
   GHIDRA_INSTALL_DIR=<absolute_path_to_your_ghidra_installation>
   ```
1. Then build with:
   ```sh
   gradle
   ```
