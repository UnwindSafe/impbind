# impbind
Adds fake imports to an executable.

## Motivation
The motivation for this project is twofold. Firstly, is to provide a new import hash for a binary. Some import hashes are a huge red flag for antiviruses.

Previous Imphash: `6d28f0f849482928a2a297579e647cb5`

New Imphash: `3017cd49a9ed31511425915c04b902af`

Secondly, is to make an executable binary seem less suspicious from analyzing imports alone.

## Install
```bash
$ git clone https://github.com/UnwindSafe/impbind.git
$ cd impbind
$ cargo build --release
```

## Usage
```
impbind - PE import spoofer tool

Usage: impbind.exe [OPTIONS] --imports <IMPORTS> <FILE>

Arguments:
  <FILE>

Options:
  -l, --list                         Show the current imports for target file
  -s, --section-name <SECTION_NAME>  The name of the custom section added for imports. default = .idata
  -i, --imports <IMPORTS>            The list of imports you want to add to target file
  -h, --help                         Print help
  -V, --version                      Print version
```

Example:
```
./impbind test.exe -i kernel32.dll!CreateFileW,kernel32.dll!AddAtomW
```
```
./impbind test.exe -l
╭───────────────────────────────────┬────────────────────────────────────────────╮
│ DLL                               ┆ Function(s)                                │
╞═══════════════════════════════════╪════════════════════════════════════════════╡
│ d3d11.dll                         ┆ D3D11CreateDeviceAndSwapChain              │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ D3DCOMPILER_43.dll                ┆ D3DCompile                                 │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ KERNEL32.dll                      ┆ GetLocaleInfoA                             │
│                                   ┆ LoadLibraryA                               │
│                                   ┆ QueryPerformanceFrequency                  │
│                                   ┆ GetProcAddress                             │
│                                   ┆ FreeLibrary                                │
│                                   ┆ QueryPerformanceCounter                    │
```
