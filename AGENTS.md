# Repository Guidelines

## Project Structure & Module Organization
This repository is a small Python CLI toolchain with all source files at the repo root.
- `elfgen.py`: main entry point; parses instruction dumps, builds block/section layouts, emits assembly/linker/C files, compiles, and runs the output binary.
- `instr_stream.py`: shared instruction-stream data structures, branch metadata, and constants used by `elfgen.py`.
- `template.lds`: base linker script copied and extended during generation.
- `README.md`: usage notes and example ranges.

Generated files are written beside the `--output` prefix (for example: `.S`, `.lds`, `_helper.c`, `.o`, `.bin`, `_stat.csv`).

## Build, Test, and Development Commands
- `python3 -m pip install capstone`: install required disassembly dependency.
- `python3 elfgen.py --help`: inspect CLI options and argument format.
- `python3 elfgen.py <bbt_dump...> --output <prefix>`: run end-to-end generation.
- `python3 -m py_compile elfgen.py instr_stream.py`: quick syntax validation before committing.

Example:
```bash
python3 elfgen.py raw_data/bbt_dump_1 --output out/bbt_elf_1
```

## Coding Style & Naming Conventions
- Target Python 3.6+ compatibility.
- Use 4-space indentation and keep line wrapping readable for long conditions.
- Follow existing naming patterns: `snake_case` for functions/variables, `CamelCase` for classes, `UPPER_CASE` for constants.
- Prefer explicit imports for new code; avoid introducing additional wildcard imports.
- Use `logging` for runtime diagnostics; keep warnings/errors actionable.

## Testing Guidelines
There is no formal automated test suite yet.
- Minimum check for any change: run `py_compile` and one representative `elfgen.py` invocation.
- Validate generated artifacts exist for the output prefix, especially `<prefix>.bin` and `<prefix>_stat.csv`.
- If you add tests, place them under `tests/` and use `pytest` with names like `test_block_split.py`.

## Commit & Pull Request Guidelines
Git history currently starts with a single baseline commit (`first commit`), so conventions are lightweight.
- Use short, imperative commit subjects (for example: `elfgen: fix conditional branch range fallback`).
- In PRs, include: purpose, exact command used for validation, and a brief summary of output changes.
- Link related issues and call out toolchain assumptions (`gcc`, ARM64 execution environment).

## Security & Configuration Tips
- Treat dump inputs as trusted internal data unless reviewed.
- The script executes the generated binary; use an isolated environment when processing unknown traces.
