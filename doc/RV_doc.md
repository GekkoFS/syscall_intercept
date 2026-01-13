# RISC-V Implementation of syscall_intercept

## Overview
The RISC-V implementation uses a **Hybrid Interception Mechanism** that prioritizes PC-relative jumps (`TYPE_JAL`) for performance and reliability, falling back to a Global Pointer-based approach (`TYPE_GP`) only when necessary.

This architecture differs from the pure "GPoline" approach by embedding small trampolines directly within the target object's memory segments, allowing for simpler 4-byte patch instructions.

## Runtime Memory Layout & Control Flow

### 1. The Components
*   **main**: The user application initiating system calls.
*   **libc (SO)**: The target shared object containing `ecall` instructions.
*   **Local Trampoline**: A small data/code block allocated within the text segment gaps of the loaded library (e.g., libc).
*   **Introduction/Global Trampoline**: The entry point in `libsyscall_intercept.so`.

### 2. Primary Execution Path: TYPE_JAL (PC-Relative)
This is the preferred method, used when a local trampoline slot is available within +/- 1MB of the syscall.

*   **The Context**: An `ecall` instruction at `0x1234`.
*   **The Patch**:
    *   The `ecall` is overwritten with `auipc t0, 0` and `jalr zero, offset(t0)`.
    *   This is a 4-byte sequence (compressed) or 8-byte sequence that jumps to the **Local Trampoline**.
    *   Returns are handled via `t0` (Link Register logic modified).
*   **The Trampoline**:
    *   Saves `ra` and `t0` (return address).
    *   Performs a full absolute jump to the `asm_entry_point` in the intercept library.

### 3. Fallback Execution Path: TYPE_GP (Global Pointer)
Used when local slots are unavailable or for specific ABI compliance.

*   **Logic**: Uses the `gp` register to access a Global Offset Table (GOT) or specific global slot.
*   **Patch**: `jalr gp` (Complete) or `jr offset(gp)` (Fail-safe).
*   **State**: Requires `gp` to be correctly initialized to point to the interception table.

## Internal Mechanics

### Trampoline Allocation
The library scans the loaded object's segments (`dl_iterate_phdr`) for small gaps of zero-filled memory (alignment padding). It `mprotect`s these gaps to be executable and writes a small trampoline stub:
1.  Save Context (`addi sp`, `sd ra`).
2.  Save Patch Return Address (`sd t0`).
3.  Absolute Jump to `libsyscall_intercept`'s entry point.

### Return Address Handling
*   **JAL Path**: The return address is stored in `t0` (or `ra` depending on exact patch variant) and saved to the stack by the trampoline *before* calling the intercept handler.
*   **Wrapper**: `detect_cur_patch_wrapper` loads this saved address to identify which syscall was called.

## Diagram
```
[ User App ]  ->  [ libc / Target DSO ]
     |                  |
     v                  v
  syscall()  ---->  [ PATCH SITE ]
                    (auipc + jalr)
                        |
                        v
                 [ LOCAL TRAMPOLINE ]
                 (Inside libc segment)
                 1. Save ra, t0
                 2. Load Absolute Addr
                 3. Jump -> -----------------+
                                             |
                                             v
                                    [ libsyscall_intercept.so ]
                                    [ asm_entry_point ]
                                    1. Save all regs
                                    2. Call handler
                                    3. Restore regs
                                    4. Jump back using saved t0/ra
```
