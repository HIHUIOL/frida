#!/usr/bin/env python3
"""
Adapt frida-kmod.c to Android 16 GKI 6.12 kernel.

Two incompatibilities, both verified against cctv18/android_gki_kernel_common
branch android16-6.12-2025-06:

1. struct kernel_symbol
   GKI 6.12 keeps its definition in kernel/module/internal.h, a header modules
   cannot include; the public linux/export.h only forward-declares it. We walk
   mod->syms[] in frida_kmod_module_at(), so mirror the layout locally.

2. task_struct.sysvsem
   Guarded by CONFIG_SYSVIPC, which GKI leaves unset (# CONFIG_SYSVIPC is not
   set). With it off the member does not exist and the code is dead anyway:
   there is no SysV undo list to inherit.

Idempotent: running twice changes nothing.
"""
import sys
import pathlib

LOCAL_STRUCT = """
/*
 * GKI keeps struct kernel_symbol in kernel/module/internal.h, which modules
 * cannot include. Mirror the layout here so mod->syms[] can be walked.
 */
struct frida_kernel_symbol {
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
  int value_offset;
  int name_offset;
  int namespace_offset;
#else
  unsigned long value;
  const char * name;
  const char * namespace;
#endif
};

"""


def patch(path: pathlib.Path) -> None:
    src = path.read_text()

    # --- 1. local struct definition, inserted before the first struct we own ---
    anchor = "struct frida_cloak_range"
    if "struct frida_kernel_symbol {" not in src:
        idx = src.index(anchor)
        src = src[:idx] + LOCAL_STRUCT + src[idx:]

    # --- 2. swap the type in every signature ---
    src = src.replace(
        "const struct kernel_symbol * sym",
        "const struct frida_kernel_symbol * sym",
    )

    # --- 3. CONFIG_SYSVIPC guard ---
    src = src.replace(
        "  void * undo_list = leader->sysvsem.undo_list;",
        "#ifdef CONFIG_SYSVIPC\n"
        "  void * undo_list = leader->sysvsem.undo_list;\n"
        "#else\n"
        "  void * undo_list = NULL;\n"
        "#endif",
    )
    src = src.replace(
        "    current->sysvsem.undo_list = undo_list;",
        "#ifdef CONFIG_SYSVIPC\n"
        "    current->sysvsem.undo_list = undo_list;\n"
        "#endif",
    )

    path.write_text(src)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: patch_frida_kmod.py <path to frida-kmod.c>", file=sys.stderr)
        return 2
    p = pathlib.Path(argv[1])
    if not p.is_file():
        print(f"not found: {p}", file=sys.stderr)
        return 2
    patch(p)
    print(f"patched: {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
