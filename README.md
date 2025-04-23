
# 3days1script

`3days1script` is a minimalist compiler and stack-based virtual machine for a simple, custom programming language. As the name suggests, the core implementation was completed in **just three days**.

This project was undertaken with significant self-imposed restrictions, primarily focusing on minimizing external dependencies and avoiding complex memory management.

*   Commit messages for this project were primarily written by **GitHub Copilot**.
*   This README and some testcode was generated with assistance from **Google Gemini 2.5 Preview (model 20240305)** and the **project author**.

## Key Features & Limitations

*   **Rapid Development:** Built in a 3-day sprint.
*   **Minimalist C:** Implemented in C with heavy restrictions:
    *   No `string.h`.
    *   No dynamic memory allocation (`malloc`, `free`, etc.). All memory is statically allocated within a large `union mem` block.
    *   Limited use of standard library functions.
*   **Single Data Type:** The language and VM **only support `int32_t`**. All values, pointers, and addresses are represented as 32-bit integers.
*   **Stack-Based "Arrays":** There is no built-in array type. Contiguous memory regions (simulating arrays) can be managed by directly manipulating the stack pointer (`sp`) and using pointer arithmetic.
    *   Example: To allocate a 10-element "array", you might get the starting address into a variable `&arr = * sp + 0` and then increment the stack pointer `*sp = *sp + 10`. Access would be `*(arr + index)`.
*   **Strict Tokenization:** All language tokens (keywords, operators, identifiers, numbers) **must** be separated by whitespace (space, tab, newline).
    *   **Exception:** The unary address-of operator (`&`) does *not* require preceding whitespace and can be directly attached to the identifier it modifies (e.g., `&my_var`).
*   **Simple VM:** Executes custom bytecode on a straightforward stack-based virtual machine architecture with instruction pointer (`ip`), stack pointer (`sp`), and base pointer (`bp`).
*   **Recursive Descent Parser:** Features a hand-written recursive descent parser to build an intermediate representation before generating bytecode.

## How it Works

1.  **Read Source:** The input script file is read into a character buffer within the `mem` union.
2.  **Parse:** The `parse()` function iterates through the source code using `token_next` and `token_eq` helpers. It builds an intermediate representation (IR) as a sequence of `node_t` structures, representing instructions, literals, variable references, and control flow. Labels are assigned unique IDs.
3.  **Compile (`tobin`):** The `tobin()` function translates the IR (`node_t` list) into integer bytecode stored directly in the `mem.i32` array.
    *   It calculates the final bytecode address for each label.
    *   It resolves jump/call targets to these addresses.
    *   It assigns stack offsets (relative to `bp`) to local variables.
    *   It sets the initial `ip`, `sp`, and `bp` values.
4.  **Execute (`exec`):** The `exec()` function runs the virtual machine loop. It fetches the instruction at `mem[ip]`, executes it (manipulating the stack `mem[sp]...` and potentially `ip` or `bp`), and continues until a halt condition (currently, an unknown instruction or program completion).

## Usage

1.  **Compile the Interpreter:**
    ```bash
    gcc 3days1script.c -o 3days1script -O2
    ```
    *(Using optimizations like `-O2` is recommended)*

2.  **Write your script:** Create a text file (e.g., `my_program.txt`) containing code written in the `3days1script` language. Remember the tokenization rules!

3.  **Run your script:**
    ```bash
    ./3days1script my_program.3d1s
    ```
    Output (e.g., from `write`) will be printed to standard output. Input (for `read`) is expected from standard input.

## Example Language Code: Mandelbrot Set

This example demonstrates rendering a simple ASCII Mandelbrot set, showcasing functions, variables, loops, conditionals, arithmetic, and I/O.

```bash
./3days1script ./test/Mandelbrot.txt
```


## Development Notes

*   The extreme limitations (no strings, no malloc, `int32_t` only, whitespace rules) were the main challenge and driver for the design.
*   The use of a `union` for memory management is a key aspect, allowing the same memory block to serve different purposes during compilation and execution.
*   Error handling is minimal. Invalid code or runtime errors may lead to undefined behavior or crashes.