"""Build minimal ELF fixtures for the M4 tool unit tests.

:mod:`pyelftools` can read but not write ELF files, so this module hand-
assembles a minimal ELF64 little-endian binary with just enough structure for
the M4 readers: program headers (``PT_GNU_STACK`` / ``PT_GNU_RELRO``),
``.dynsym`` / ``.symtab`` with imports, an optional ``.dynamic`` section, and
``.rodata`` strings.
"""

from __future__ import annotations

import struct
from pathlib import Path

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

SHN_UNDEF = 0

STB_GLOBAL = 1
STT_FUNC = 2

DT_NULL = 0
DT_BIND_NOW = 24

PF_R = 4
PF_W = 2
PF_X = 1


def _ident() -> bytes:
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2  # 64-bit
    ident[5] = 1  # little-endian
    ident[6] = 1  # ELF version
    return bytes(ident)


def _elf_header(
    e_type: int,
    e_phoff: int,
    e_shoff: int,
    e_phnum: int,
    e_shnum: int,
    e_shstrndx: int,
) -> bytes:
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        _ident(),
        e_type,
        EM_X86_64,
        1,  # e_version
        0,  # e_entry
        e_phoff,
        e_shoff,
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        e_phnum,
        64,  # e_shentsize
        e_shnum,
        e_shstrndx,
    )


def _phdr(p_type: int, p_flags: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, p_flags, 0, 0, 0, 0, 0, 0)


def _shdr(
    sh_name: int,
    sh_type: int,
    sh_offset: int,
    sh_size: int,
    sh_link: int,
    sh_entsize: int,
) -> bytes:
    return struct.pack(
        "<IIQQQQIIQQ", sh_name, sh_type, 0, 0, sh_offset, sh_size, sh_link, 0, 1, sh_entsize
    )


def _sym(st_name: int, st_info: int, st_shndx: int) -> bytes:
    return struct.pack("<IBBHQQ", st_name, st_info, 0, st_shndx, 0, 0)


def _null_sym() -> bytes:
    return _sym(0, 0, 0)


def _strtab(names: list[str]) -> tuple[bytes, dict[str, int]]:
    data = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(data)
        data.extend(name.encode("ascii"))
        data.extend(b"\x00")
    return bytes(data), offsets


def build_elf64(
    *,
    e_type: int = ET_DYN,
    has_gnu_stack: bool = True,
    stack_executable: bool = False,
    has_relro: bool = True,
    bind_now: bool = False,
    has_symtab: bool = True,
    imports: list[str] | None = None,
    defined_syms: list[str] | None = None,
    rodata_strings: list[str] | None = None,
    canary: bool = False,
) -> bytes:
    """Assemble a minimal ELF64 file and return its bytes."""
    imports = list(imports or [])
    defined_syms = list(defined_syms or [])
    rodata_strings = list(rodata_strings or [])
    if canary:
        imports = [*imports, "__stack_chk_fail"]

    # Content blobs.
    dynstr, dyn_offsets = _strtab(imports)
    dynsym = _null_sym() + b"".join(
        _sym(dyn_offsets[n], (STB_GLOBAL << 4) | STT_FUNC, SHN_UNDEF) for n in imports
    )

    strtab, str_offsets = _strtab(defined_syms)
    symtab = _null_sym() + b"".join(
        _sym(str_offsets[n], (STB_GLOBAL << 4) | STT_FUNC, 1) for n in defined_syms
    )

    rodata = b"\x00".join(s.encode("ascii") for s in rodata_strings)
    if rodata:
        rodata += b"\x00"

    dynamic = b""
    if bind_now:
        dynamic = struct.pack("<QQ", DT_BIND_NOW, 0) + struct.pack("<QQ", DT_NULL, 0)

    # Build an ordered section plan: (name, type, data, link, entsize).
    plan: list[tuple[str, int, bytes, int, int]] = []
    plan.append((".dynstr", SHT_STRTAB, dynstr, 0, 0))
    plan.append((".dynsym", SHT_DYNSYM, dynsym, 0, 24))  # link patched below
    if has_symtab:
        plan.append((".strtab", SHT_STRTAB, strtab, 0, 0))
        plan.append((".symtab", SHT_SYMTAB, symtab, 0, 24))  # link patched below
    plan.append((".rodata", SHT_PROGBITS, rodata, 0, 0))
    if bind_now:
        plan.append((".dynamic", SHT_DYNAMIC, dynamic, 0, 16))

    # Section names string table (.shstrtab) covers every section name.
    all_names = [".shstrtab"] + [name for name, *_ in plan]
    shstrtab, shstr_offsets = _strtab(all_names)

    # Index map: null(0) + .shstrtab(1) + plan sections (2..n).
    idx: dict[str, int] = {}
    next_idx = 2
    for name, *_ in plan:
        idx[name] = next_idx
        next_idx += 1

    # Patch link fields: dynsym -> dynstr, symtab -> strtab, dynamic -> dynstr.
    patched: list[tuple[str, int, bytes, int, int]] = []
    for name, stype, data, _link, entsize in plan:
        link = 0
        if name in (".dynsym", ".dynamic"):
            link = idx[".dynstr"]
        elif name == ".symtab":
            link = idx[".strtab"]
        patched.append((name, stype, data, link, entsize))
    plan = patched

    # Program headers come right after the ELF header.
    phnum = int(has_gnu_stack) + int(has_relro)
    base = 64 + 56 * phnum

    # Assign file offsets for each section (starting right after the phdrs).
    offsets: list[int] = []
    cursor = base
    for _name, _stype, data, _link, _entsize in plan:
        offsets.append(cursor)
        cursor += len(data)

    # .shstrtab data sits after all plan-section data.
    shstrtab_off = cursor
    shoff = shstrtab_off + len(shstrtab)

    # Build section header table (null + .shstrtab + plan sections).
    shdrs = [_shdr(0, SHT_NULL, 0, 0, 0, 0)]
    shdrs.append(_shdr(shstr_offsets[".shstrtab"], SHT_STRTAB, shstrtab_off, len(shstrtab), 0, 0))
    for (name, stype, data, link, entsize), sec_off in zip(plan, offsets, strict=True):
        shdrs.append(_shdr(shstr_offsets[name], stype, sec_off, len(data), link, entsize))

    shnum = len(shdrs)
    shstrndx = 1

    section_data = b"".join(data for _n, _t, data, _l, _e in plan) + shstrtab
    section_table = b"".join(shdrs)

    phdrs: list[bytes] = []
    if has_gnu_stack:
        flags = (PF_R | PF_W) | (PF_X if stack_executable else 0)
        phdrs.append(_phdr(PT_GNU_STACK, flags))
    if has_relro:
        phdrs.append(_phdr(PT_GNU_RELRO, PF_R))

    header = _elf_header(e_type, 64, shoff, phnum, shnum, shstrndx)
    return header + b"".join(phdrs) + section_data + section_table


def write_elf64(path: str | Path, **kwargs: object) -> Path:
    """Write a minimal ELF64 to ``path`` and return it as a ``Path``."""
    target = Path(path)
    target.write_bytes(build_elf64(**kwargs))
    return target


EM_MIPS = 8
SHF_ALLOC = 2
SHF_EXECINSTR = 4
SHF_WRITE = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_PLTGOT = 3
DT_MIPS_LOCAL_GOTNO = 0x7000000A
DT_MIPS_GOTSYM = 0x70000013
DT_MIPS_SYMTABNO = 0x70000011


def _u32be(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def build_mips32_pic_elf(*, import_name: str = "strcpy", func_name: str = "helper") -> bytes:
    """Assemble a MIPS32 big-endian PIC ELF with one ``jalr $t9`` import call.

    Layout is chosen so o32 ``$gp`` recovery in ``tools.binary.call_chain`` can
    resolve ``import_name`` through ``.got`` without Ghidra.
    """
    text_addr = 0x1000
    got_addr = 0x2000
    local_gotno = 4
    strcpy_slot = got_addr + local_gotno * 4  # 0x2010
    gp_at_entry = got_addr + 0x7FF0  # 0x9FF0
    gp_const = (gp_at_entry - text_addr) & 0xFFFFFFFF  # 0x8FF0
    lui_imm = gp_const >> 16  # 0
    addiu_imm = gp_const & 0xFFFF  # 0x8FF0, but lui must be 1 when addiu is negative
    if addiu_imm >= 0x8000:
        lui_imm += 1
        addiu_imm = (addiu_imm - 0x10000) & 0xFFFF
    gp_off = (strcpy_slot - gp_at_entry) & 0xFFFF  # -0x7FE0

    text = b"".join(
        [
            _u32be(0x3C1C0000 | lui_imm),  # lui $gp, lui_imm
            _u32be(0x279C0000 | addiu_imm),  # addiu $gp, $gp, addiu_imm
            _u32be(0x0399E021),  # addu $gp, $gp, $t9
            _u32be(0x27BDFFD8),  # addiu $sp, $sp, -0x28
            _u32be(0xAFBF0024),  # sw $ra, 0x24($sp)
            _u32be(0x8F990000 | gp_off),  # lw $t9, gp_off($gp)
            _u32be(0x0320F809),  # jalr $t9
            _u32be(0x00000000),  # nop
            _u32be(0x8FBF0024),  # lw $ra, 0x24($sp)
            _u32be(0x03E00008),  # jr $ra
            _u32be(0x27BD0028),  # addiu $sp, $sp, 0x28
        ]
    )

    dynstr = b"\x00" + func_name.encode() + b"\x00" + import_name.encode() + b"\x00"
    func_off, import_off = 1, 1 + len(func_name) + 1
    # ELF32 dynsym: st_name, st_value, st_size, st_info, st_other, st_shndx
    dynsym = (
        struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0)
        + struct.pack(">IIIBBH", func_off, text_addr, len(text), (STB_GLOBAL << 4) | STT_FUNC, 0, 6)
        + struct.pack(">IIIBBH", import_off, 0x3000, 0, (STB_GLOBAL << 4) | STT_FUNC, 0, SHN_UNDEF)
    )
    got = b"\x00" * (local_gotno * 4) + _u32be(0x3000)
    dynamic = b"".join(
        struct.pack(">II", tag, val)
        for tag, val in (
            (DT_PLTGOT, got_addr),
            (DT_SYMTAB, 0),  # patched after layout
            (DT_STRTAB, 0),
            (DT_MIPS_LOCAL_GOTNO, local_gotno),
            (DT_MIPS_GOTSYM, 2),
            (DT_MIPS_SYMTABNO, 3),
            (DT_NULL, 0),
        )
    )

    shstrtab, sh_off = _strtab([".shstrtab", ".dynstr", ".dynsym", ".dynamic", ".got", ".text"])
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 1
    ident[5] = 2
    ident[6] = 1

    ehdr_size, phdr_size, shdr_size = 52, 32, 40
    phnum = 1
    cursor = ehdr_size + phdr_size * phnum

    def _align(value: int, align: int) -> int:
        return (value + align - 1) & ~(align - 1)

    dynstr_off = cursor
    dynsym_off = dynstr_off + len(dynstr)
    dynamic_off = dynsym_off + len(dynsym)
    got_off = _align(dynamic_off + len(dynamic), 4)
    text_off = got_off + len(got)
    shstr_off = text_off + len(text)
    shoff = shstr_off + len(shstrtab)

    dynstr_addr = 0x4000
    dynsym_addr = dynstr_addr + len(dynstr)
    dynamic_addr = 0x5000
    # Patch DT_SYMTAB / DT_STRTAB now that addresses are known.
    dynamic = b"".join(
        struct.pack(">II", tag, val)
        for tag, val in (
            (DT_PLTGOT, got_addr),
            (DT_SYMTAB, dynsym_addr),
            (DT_STRTAB, dynstr_addr),
            (DT_MIPS_LOCAL_GOTNO, local_gotno),
            (DT_MIPS_GOTSYM, 2),
            (DT_MIPS_SYMTABNO, 3),
            (DT_NULL, 0),
        )
    )

    def shdr(
        name: str,
        sh_type: int,
        flags: int,
        addr: int,
        offset: int,
        size: int,
        link: int = 0,
        info: int = 0,
        align: int = 4,
        entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            ">10I",
            sh_off[name],
            sh_type,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            align,
            entsize,
        )

    shdrs = b"".join(
        [
            struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            shdr(".shstrtab", SHT_STRTAB, 0, 0, shstr_off, len(shstrtab)),
            shdr(".dynstr", SHT_STRTAB, SHF_ALLOC, dynstr_addr, dynstr_off, len(dynstr)),
            shdr(
                ".dynsym",
                SHT_DYNSYM,
                SHF_ALLOC,
                dynsym_addr,
                dynsym_off,
                len(dynsym),
                link=2,
                info=1,
                entsize=16,
            ),
            shdr(
                ".dynamic",
                SHT_DYNAMIC,
                SHF_ALLOC | SHF_WRITE,
                dynamic_addr,
                dynamic_off,
                len(dynamic),
                link=2,
                entsize=8,
            ),
            shdr(".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, got_addr, got_off, len(got)),
            shdr(
                ".text",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                text_addr,
                text_off,
                len(text),
                align=16,
            ),
        ]
    )
    phdr = struct.pack(
        ">8I",
        1,  # PT_LOAD
        text_off,
        text_addr,
        text_addr,
        len(text),
        len(text),
        PF_R | PF_X,
        0x1000,
    )
    header = struct.pack(
        ">16sHHIIIIIHHHHHH",
        bytes(ident),
        ET_DYN,
        EM_MIPS,
        1,
        text_addr,
        ehdr_size,
        shoff,
        0x50001007,
        ehdr_size,
        phdr_size,
        phnum,
        shdr_size,
        7,
        1,
    )
    blob = bytearray(shoff + len(shdrs))
    blob[0:ehdr_size] = header
    blob[ehdr_size : ehdr_size + phdr_size] = phdr
    blob[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    blob[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    blob[dynamic_off : dynamic_off + len(dynamic)] = dynamic
    blob[got_off : got_off + len(got)] = got
    blob[text_off : text_off + len(text)] = text
    blob[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    blob[shoff:] = shdrs
    return bytes(blob)


def write_mips32_pic_elf(path: str | Path, **kwargs: object) -> Path:
    """Write a MIPS32 PIC ELF that calls ``import_name`` via GOT/jalr."""
    target = Path(path)
    target.write_bytes(build_mips32_pic_elf(**kwargs))
    return target
