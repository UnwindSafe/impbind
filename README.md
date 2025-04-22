# impbind
Adds fake imports to an executable.

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
