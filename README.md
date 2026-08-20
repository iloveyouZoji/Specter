# Specter

**Specter** is a Windows-focused C++ project built around low-level PE inspection, runtime module discovery, and dynamic function resolution.

## Features

* **PEB-based module discovery**
* **PE export-table parsing**
* **Compile-time identifier hashing**
* **Runtime function resolution**
* **Typed function pointers**
* **Minimal conventional imports**
* **Low-level Windows API interaction**

## Architecture

| Component               | Description                                                          |
| ----------------------- | -------------------------------------------------------------------- |
| **Module Discovery**    | Locates loaded Windows modules through process-level structures.     |
| **Export Resolution**   | Works with PE export metadata to identify exported functions.        |
| **Hashing**             | Uses compile-time hashes to represent selected function identifiers. |
| **Function Resolution** | Resolves required functions dynamically at runtime.                  |
| **Function Pointers**   | Uses explicit function signatures for resolved APIs.                 |
| **Import Footprint**    | Keeps the conventional import footprint minimal.                     |

## PE Internals

Specter interacts with structures provided by the Windows Portable Executable format, including module metadata and export information. Microsoft's PE documentation describes the export directory and the tables used to associate exported names, ordinals, and addresses.

### Resolution Flow

```text
Process
   │
   ▼
Module Discovery
   │
   ▼
PE Export Metadata
   │
   ▼
Identifier Matching
   │
   ▼
Function Address
   │
   ▼
Typed Function Pointer
```

## Project Structure

```text
Specter/
├── specter.cpp
├── README.md
├── LICENSE
└── .gitignore
```

## Requirements

* Windows
* C++17 or newer
* MSVC or another compatible C++ compiler

## Documentation

* [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
* [Microsoft PE Format — Export Tables](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)

## Repository

**GitHub:** https://github.com/iloveyouZoji/Specter

## License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
