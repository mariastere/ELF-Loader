# Custom ELF Loader for Linux

## 📌 Overview
This project is a custom, minimalistic **ELF (Executable and Linkable Format) loader** designed for Linux systems. The loader mimics the behavior of the Linux kernel's `execve` family by manually parsing, loading, and executing statically linked ELF binaries directly into memory. 

The implementation dives deep into virtual memory management, process memory layout, execution flow hijacking, and stack initialization.

## 🚀 Features & Capabilities

The loader successfully handles and executes various types of ELF binaries:

1. **Syscall-Only Binaries:** 
   - Minimal binaries (often written in pure assembly) that make direct Linux syscalls without relying on `libc`.
2. **Statically Linked Non-PIE Binaries:** 
   - Standard static C programs compiled with `libc` (e.g., `gcc -static`).
3. **Statically Linked PIE (Position Independent Executables):** 
   - `ET_DYN` type binaries mapped at a random base address, requiring manual relocation of entry points and program headers.

## ⚙️ Core Implementation Details

### 1. ELF Header Validation
- Verifies the ELF magic number and ensures the binary is a valid **64-bit ELF (`ELFCLASS64`)** before proceeding.
- Graceful error handling and specific exit codes (3 or 4) for invalid binaries.

### 2. Virtual Memory Mapping & Permissions
- Parses the **Program Headers (`PT_LOAD`)** to identify memory segments.
- Uses `mmap()` and `mprotect()` to map file segments into virtual memory with the correct permissions (`PF_R`, `PF_W`, `PF_X`), mimicking the exact behavior of the kernel loader.
- Handles discrepancies between file size (`p_filesz`) and memory size (`p_memsz`), zero-initializing the `.bss` section.

### 3. Stack Initialization & Layout
To successfully run `libc`-linked binaries, the loader manually constructs the execution stack layout expected by the program before jumping to its entry point. This includes:
- **`argc` & `argv`**: Parsing command-line arguments and pushing them onto the new stack.
- **`envp`**: Copying the environment variables array.
- **`auxv` (Auxiliary Vector)**: Manually constructing the key-value pairs used by the kernel to pass system information to user space (e.g., `AT_PAGESZ`, `AT_PHDR`, `AT_NULL`). Special attention is given to the `AT_RANDOM` entry to prevent `glibc` crashes during initialization.

### 4. Execution Transfer
- Calculates the final entry point (adjusting for the load base in the case of PIE binaries).
- Uses inline assembly to pivot the stack pointer (`%rsp`) to the newly created stack, clears registers, and performs a direct jump (`jmp`) to the ELF entry point.

## 🛠️ Tools & Technologies Used
* **C / Inline x86_64 Assembly**
* **POSIX APIs:** `mmap`, `mprotect`, `open`, `read`
* **Debugging Tools:** `gdb` (with `gef`/`pwngdb`), `readelf`, `objdump`, `pmap`
* **Concepts:** Virtual Memory Layout, Page Faults, Executable Formats, OS Process Initialization.

## 🏃‍♂️ How to Run

Compile the loader using the provided Makefile:
```bash
make
