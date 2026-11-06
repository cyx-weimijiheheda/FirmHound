"""Lightweight call-chain recovery for stripped ARM32 / MIPS ELF (no Ghidra).

DECOMPILE fallback that answers the questions the verifier needs for a
``command_injection``/``overflow`` candidate:

1. which code locations call a sink import (``system`` / ``doSystemCmd`` /
   ``popen`` / ``strcpy`` ...);
2. whether the *enclosing function* of that call site also calls a source API
   (``websGetVar`` / ``websGetVar64`` / ``parse_special_char`` ...) --
   same-function co-location;
3. which web handler name a function serves. Registration is recovered by a
   *generic* GoAhead pattern that does NOT depend on ``websFormDefine`` being a
   dynamic import (Tenda links it statically): scan every call site, and when
   the caller loads ``r0 = "formXxx..."`` (printable, ``form*``/``from*``) and
   ``r1 = <code address>`` immediately before the call, record
   ``name -> func_addr``. This yields the handler table even when the registrar
   itself is a local function.

ARM32 uses ``bl``/``blx`` + PLT. MIPS uses PIC ``jalr $t9`` through GOT stubs
(``DT_MIPS_GOTSYM``). Both paths are pure Python (``pyelftools`` + ``capstone``).
If a step is inconclusive the module degrades honestly to an empty report -- it
never fabricates a chain.
"""

from __future__ import annotations

import bisect
import re
import struct
from pathlib import Path
from typing import Any

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_MIPS,
    CS_MODE_ARM,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    Cs,
)

from tools.binary.elf_read import canonical_arch, iter_exports, load_elf

# Canonical architecture names (from tools.binary.elf_read.canonical_arch) that
# the current recovery implementation can disassemble.
SUPPORTED_ARCHES = frozenset({"arm", "arm32", "mips", "mipsel"})

DEFAULT_SOURCE_APIS = (
    "websGetVar",
    "websGetVar64",
    "websGetVarLen",
    "httpdGetChar",
    "websDecodeUrl",
    "websGetQuery",
    "websGetRequest",
    "getenv",
    "parse_special_char",
    "get_cgi",
    "nvram_safe_get",
    "nvram_get",
)

DEFAULT_FILTER_APIS = (
    "strncmp",
    "strcmp",
    "atoi",
    "strlen",
    "sscanf",
    "strtol",
    "strtoul",
    "isalpha",
    "isdigit",
)

_FORM_NAME_RE = re.compile(r"^(form|from)[A-Za-z0-9_]{2,}$")
_WINDOW = 14


def _exec_sections(elf: Any) -> list[dict[str, Any]]:
    out = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_PROGBITS" and section["sh_flags"] & 0x4:
            data = section.data()
            if data:
                out.append({"name": section.name, "addr": section["sh_addr"], "data": data})
    return out


def _build_view(elf: Any) -> tuple[list[tuple[int, bytes]], list[tuple[int, int]]]:
    """One-time view of PROGBITS sections: (base, data) + (base, end) ranges."""
    sections: list[tuple[int, bytes]] = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_PROGBITS":
            data = section.data()
            if data:
                sections.append((section["sh_addr"], data))
    ranges = [(base, base + len(data)) for base, data in sections]
    return sections, ranges


def _read_at(view: list[tuple[int, bytes]], va: int, size: int) -> bytes | None:
    for base, data in view:
        off = va - base
        if 0 <= off <= len(data) - size:
            return data[off : off + size]
    return None


def _read_string(view: list[tuple[int, bytes]], va: int, max_len: int = 128) -> str | None:
    raw = _read_at(view, va, max_len)
    if raw is None:
        return None
    end = raw.find(b"\x00")
    if end < 0:
        return None
    text = raw[:end]
    if not text or not all(0x20 <= byte < 0x7F for byte in text):
        return None
    return text.decode("ascii", "ignore")


def _plt_map(elf: Any) -> dict[int, str]:
    """Map PLT stub start -> import name (ARM JUMP_SLOT order == PLT order)."""
    plt_sec = next((s for s in elf.iter_sections() if s.name == ".plt"), None)
    dynsym = elf.get_section_by_name(".dynsym")
    if plt_sec is None or dynsym is None:
        return {}
    slots: list[tuple[int, int]] = []
    for reloc_name in (".rel.plt", ".rela.plt"):
        reloc = elf.get_section_by_name(reloc_name)
        if reloc is None:
            continue
        for r in reloc.iter_relocations():
            if r["r_info_type"] in {2, 7, 21, 22}:
                slots.append((r["r_info_sym"], r["r_offset"]))
    if not slots:
        return {}
    slots.sort(key=lambda pair: pair[1])
    plt_base = plt_sec["sh_addr"]
    header = plt_sec["sh_size"] - 12 * len(slots)
    if header < 0:
        header = 16
    out: dict[int, str] = {}
    for i, (sym_index, _offset) in enumerate(slots):
        try:
            sym = dynsym.get_symbol(sym_index)
        except Exception:  # noqa: BLE001
            continue
        if sym is not None and sym.name:
            out[plt_base + header + i * 12] = sym.name
    return out


def _dest_reg(op_str: str) -> str:
    return op_str.split(",")[0].strip()


def _literal_values(
    view: list[tuple[int, bytes]], window: list[tuple[int, str, str]], reg: str
) -> list[int]:
    """Values loaded into ``reg`` within the window (ldr pc-relative/ADR/movw-movt)."""
    values: list[int] = []
    for addr, mnemonic, op_str in reversed(window):
        if _dest_reg(op_str) != reg:
            continue
        try:
            imm = int(re.search(r"#(0x[0-9a-fA-F]+|\d+)", op_str).group(1), 0)
        except (AttributeError, ValueError):
            imm = None
        if mnemonic == "ldr" and imm is not None and "[pc" in op_str:
            raw = _read_at(view, ((addr + 8) & ~3) + imm, 4)
            if raw is not None:
                values.append(struct.unpack("<I", raw)[0])
        elif mnemonic in {"add", "adr"} and imm is not None:
            values.append(((addr + 8) & ~3) + imm)
        elif mnemonic == "movw" and imm is not None:
            values.append(imm)
        elif mnemonic == "movt" and imm is not None and values:
            values[-1] |= imm << 16
        if len(values) >= 4:
            break
    return values


def _empty_ok() -> dict[str, Any]:
    return {
        "status": "ok",
        "sink_callers": [],
        "registration": {},
        "func_handlers": {},
        "chains": [],
    }


def _sign_extend16(value: int) -> int:
    return value - 0x10000 if value >= 0x8000 else value


def _parse_imm(op_str: str) -> int | None:
    match = re.search(r"(-?0x[0-9a-fA-F]+|-?\d+)", op_str)
    if match is None:
        return None
    return int(match.group(1), 0)


def _mips_dyn_tag(elf: Any, tag: str) -> int | None:
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        return None
    for item in dynamic.iter_tags():
        if item.entry.d_tag == tag:
            return int(item.entry.d_val)
    return None


def _mips_got_map(elf: Any) -> dict[int, str]:
    """Map MIPS GOT stub addresses (``.got`` entries) to import names.

    o32 PIC calls ``jalr $t9`` after ``lw $t9, gp_off($gp)``. The loaded word is
    the lazy-binding stub stored in ``.got``; matching that stub against
    ``.dynsym`` recovers the import name without walking the PLT.
    """
    got = elf.get_section_by_name(".got")
    dynsym = elf.get_section_by_name(".dynsym")
    if got is None or dynsym is None:
        return {}
    got_base = int(got["sh_addr"])
    data = got.data()
    endian = ">" if elf.header["e_ident"]["EI_DATA"] == "ELFDATA2MSB" else "<"
    local_gotno = _mips_dyn_tag(elf, "DT_MIPS_LOCAL_GOTNO") or 0
    gotsym = _mips_dyn_tag(elf, "DT_MIPS_GOTSYM")
    mapping: dict[int, str] = {}
    if gotsym is not None:
        for index, symbol in enumerate(dynsym.iter_symbols()):
            if index < gotsym:
                continue
            if not symbol.name:
                continue
            slot = got_base + (local_gotno + (index - gotsym)) * 4
            mapping[slot] = symbol.name
        if mapping:
            return mapping
    stub_to_name: dict[int, str] = {}
    for symbol in dynsym.iter_symbols():
        if symbol["st_shndx"] == "SHN_UNDEF" and symbol.name and int(symbol["st_value"]):
            stub_to_name[int(symbol["st_value"])] = symbol.name
    if not stub_to_name:
        return {}
    for offset in range(0, len(data) - 3, 4):
        stub = struct.unpack(f"{endian}I", data[offset : offset + 4])[0]
        name = stub_to_name.get(stub)
        if name:
            mapping[got_base + offset] = name
    return mapping


def _scan_mips(
    sections: list[dict[str, Any]],
    *,
    little_endian: bool,
) -> tuple[list[dict[str, Any]], list[int]]:
    """Linear-scan MIPS32 ``.text`` for ``jalr $t9`` call sites and frames."""
    mode = CS_MODE_MIPS32 + (CS_MODE_LITTLE_ENDIAN if little_endian else CS_MODE_BIG_ENDIAN)
    md = Cs(CS_ARCH_MIPS, mode)
    calls: list[dict[str, Any]] = []
    prologues: list[int] = []
    pending_t9_slot: int | None = None
    last_frame: int | None = None
    pending_pic: int | None = None

    for sec in sections:
        data = sec["data"]
        base = sec["addr"]
        pos = 0
        addr = base
        while pos <= len(data) - 4:
            decoded = list(md.disasm(data[pos : pos + 65536], addr))
            if not decoded:
                pos += 4
                addr += 4
                continue
            for insn in decoded:
                mnem = insn.mnemonic
                op_str = insn.op_str
                if mnem == "lui" and op_str.startswith("$gp,"):
                    pending_pic = insn.address
                elif mnem == "addu" and "$gp, $gp, $t9" in op_str and pending_pic is not None:
                    prologues.append(pending_pic)
                    pending_pic = None
                    last_frame = None
                elif mnem == "addiu" and op_str.startswith("$sp, $sp,"):
                    imm = _parse_imm(op_str)
                    if imm is not None and imm < 0:
                        last_frame = insn.address
                elif mnem == "sw" and "$ra," in op_str and "($sp)" in op_str:
                    if last_frame is not None:
                        if not prologues or last_frame - prologues[-1] > 0x20:
                            prologues.append(last_frame)
                        last_frame = None
                    elif not prologues or insn.address - prologues[-1] > 0x20:
                        prologues.append(insn.address)
                elif mnem == "lw" and "$t9," in op_str and "($gp)" in op_str:
                    pending_t9_slot = _parse_imm(op_str.split(",")[1])
                elif mnem == "jalr" and "$t9" in op_str:
                    calls.append(
                        {
                            "addr": insn.address,
                            "target": None,
                            "name": None,
                            "gp_off": pending_t9_slot,
                            "window": (),
                        }
                    )
                    pending_t9_slot = None
                elif mnem in {"jal", "bal"}:
                    target = _parse_imm(op_str)
                    calls.append(
                        {
                            "addr": insn.address,
                            "target": target,
                            "name": None,
                            "gp_off": None,
                            "window": (),
                        }
                    )
            last = decoded[-1]
            pos += (last.address - addr) + last.size
            addr = last.address + last.size
    return calls, prologues


def _resolve_mips_call_names(
    calls: list[dict[str, Any]],
    got_map: dict[int, str],
    sections: list[dict[str, Any]],
    *,
    little_endian: bool,
) -> None:
    """Fill ``name`` on jalr sites using recovered $gp from each function.

    o32 PIC: ``lui $gp,imm; addiu $gp,imm; addu $gp,$gp,$t9`` with ``$t9`` equal
    to the function address at entry. GOT slot = gp + signed(gp_off).
    """
    if not got_map:
        return
    mode = CS_MODE_MIPS32 + (CS_MODE_LITTLE_ENDIAN if little_endian else CS_MODE_BIG_ENDIAN)
    md = Cs(CS_ARCH_MIPS, mode)
    func_gp: dict[int, int] = {}
    for sec in sections:
        decoded = list(md.disasm(sec["data"], sec["addr"]))
        i = 0
        while i < len(decoded) - 2:
            a, b, c = decoded[i], decoded[i + 1], decoded[i + 2]
            if (
                a.mnemonic == "lui"
                and a.op_str.startswith("$gp,")
                and b.mnemonic == "addiu"
                and b.op_str.startswith("$gp, $gp,")
                and c.mnemonic == "addu"
                and "$gp, $gp, $t9" in c.op_str
            ):
                hi = _parse_imm(a.op_str) or 0
                lo = _parse_imm(b.op_str) or 0
                gp_const = ((hi << 16) + lo) & 0xFFFFFFFF
                func_gp[a.address] = gp_const
                i += 3
                continue
            i += 1

    gp_starts = sorted(func_gp)
    for ev in calls:
        if ev.get("name") or ev.get("gp_off") is None:
            continue
        idx = bisect.bisect_right(gp_starts, ev["addr"]) - 1
        if idx < 0:
            continue
        func_addr = gp_starts[idx]
        gp = (func_gp[func_addr] + func_addr) & 0xFFFFFFFF
        slot = (gp + _sign_extend16(int(ev["gp_off"]) & 0xFFFF)) & 0xFFFFFFFF
        ev["name"] = got_map.get(slot)
        ev["target"] = slot


def _func_symbol_map(elf: Any) -> dict[int, str]:
    """Map defined function addresses to export names when the ELF is not stripped."""
    mapping: dict[int, str] = {}
    try:
        for name, addr in iter_exports(elf):
            if addr:
                mapping[addr] = name
    except Exception:  # noqa: BLE001 - optional enrichment, never abort
        return mapping
    return mapping


def _assemble_sink_callers(
    calls: list[dict[str, Any]],
    prologues: list[int],
    sinks: set[str],
    srcs: set[str],
    filters: set[str],
    func_names: dict[int, str] | None = None,
) -> list[dict[str, Any]]:
    named = [item for item in calls if item.get("name")]
    if not named:
        return []
    starts = sorted(set(prologues))
    names = func_names or {}
    sink_callers: list[dict[str, Any]] = []
    for ev in named:
        if ev["name"] not in sinks:
            continue
        idx = bisect.bisect_right(starts, ev["addr"]) - 1
        func_addr = starts[idx] if idx >= 0 else None
        func_name = names.get(func_addr) if func_addr is not None else None
        rec: dict[str, Any] = {
            "call_addr": ev["addr"],
            "func_addr": func_addr,
            "func_name": func_name,
            "sink": ev["name"],
            "same_func_source": bool(func_name and func_name in srcs),
            "same_func_filters": [],
        }
        if func_addr is not None:
            end = starts[idx + 1] if idx + 1 < len(starts) else ev["addr"] + 0x2000
            for other in named:
                if func_addr <= other["addr"] < end:
                    if other["name"] in srcs:
                        rec["same_func_source"] = True
                    if other["name"] in filters:
                        rec["same_func_filters"].append(other["name"])
        sink_callers.append(rec)
    return sink_callers


def _chains_from_callers(
    sink_callers: list[dict[str, Any]],
    func_handlers: dict[int, str],
) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    for caller in sink_callers:
        func_addr = caller.get("func_addr")
        if func_addr is None:
            continue
        chains.append(
            {
                "handler": func_handlers.get(func_addr),
                "func_addr": func_addr,
                "sink": caller["sink"],
                "call_addr": caller["call_addr"],
                "same_func_source": bool(caller.get("same_func_source")),
            }
        )
    return chains


def _recover_mips(
    elf: Any,
    sink_functions: list[str],
    source_apis: tuple[str, ...],
    filter_apis: tuple[str, ...],
) -> dict[str, Any]:
    sections = _exec_sections(elf)
    if not sections:
        return {"status": "failed", "reason": "no executable sections"}
    got_map = _mips_got_map(elf)
    little = bool(elf.little_endian)
    calls, prologues = _scan_mips(sections, little_endian=little)
    _resolve_mips_call_names(calls, got_map, sections, little_endian=little)
    if not calls:
        return _empty_ok()
    sink_callers = _assemble_sink_callers(
        calls,
        prologues,
        set(sink_functions),
        set(source_apis),
        set(filter_apis),
        func_names=_func_symbol_map(elf),
    )
    return {
        "status": "ok",
        "sink_callers": sink_callers,
        "registration": {},
        "func_handlers": {},
        "chains": _chains_from_callers(sink_callers, {}),
    }


def recover_chains(
    elf_path: str | Path,
    sink_functions: list[str],
    source_apis: tuple[str, ...] = DEFAULT_SOURCE_APIS,
    filter_apis: tuple[str, ...] = DEFAULT_FILTER_APIS,
) -> dict[str, Any]:
    """Recover sink call sites + handler registrations for one ARM/MIPS ELF.

    Returns:
        {"status": "ok" | "failed" | "unsupported-arch",
         "sink_callers": [{call_addr, func_addr, sink, same_func_source,
                           same_func_filters}],
         "registration": {handler: func_addr},
         "func_handlers": {func_addr: handler},   # reverse of registration
         "chains": [{handler|None, func_addr, sink, call_addr,
                     same_func_source}]}
    """
    elf = load_elf(elf_path)
    if elf is None:
        return {"status": "failed", "reason": "cannot load ELF"}
    arch = canonical_arch(elf)
    if arch not in SUPPORTED_ARCHES:
        return {"status": "unsupported-arch", "machine": str(elf["e_machine"])}
    if arch in {"mips", "mipsel"}:
        return _recover_mips(elf, sink_functions, source_apis, filter_apis)

    sections = _exec_sections(elf)
    if not sections:
        return {"status": "failed", "reason": "no executable sections"}
    view, all_ranges = _build_view(elf)
    plt = _plt_map(elf)
    sinks = set(sink_functions)
    srcs = set(source_apis)
    filters = set(filter_apis)
    exec_ranges = [(s["addr"], s["addr"] + len(s["data"])) for s in sections]
    rodata_ranges = [
        (lo, hi)
        for lo, hi in all_ranges
        if not any(xlo <= lo and hi <= xhi for xlo, xhi in exec_ranges)
    ]

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    calls: list[dict[str, Any]] = []
    prologues: list[int] = []
    window: list[tuple[int, str, str]] = []

    for sec in sections:
        data = sec["data"]
        base = sec["addr"]
        pos = 0
        addr = base
        while pos <= len(data) - 4:
            chunk = data[pos : pos + 65536]
            decoded = list(md.disasm(chunk, addr))
            if not decoded:
                pos += 4
                addr += 4
                continue
            for insn in decoded:
                mnem = insn.mnemonic
                op_str = insn.op_str
                window.append((insn.address, mnem, op_str))
                if len(window) > _WINDOW:
                    window.pop(0)
                if mnem in {"bl", "blx"}:
                    target = None
                    if insn.operands and insn.operands[0].type == 2:
                        target = int(insn.operands[0].imm)
                    calls.append(
                        {
                            "addr": insn.address,
                            "target": target,
                            "name": plt.get(target) if target is not None else None,
                            "window": tuple(window),
                        }
                    )
                elif mnem == "push" and "lr" in op_str:
                    prologues.append(insn.address)
            last = decoded[-1]
            pos += (last.address - addr) + last.size
            addr = last.address + last.size

    if not calls:
        return _empty_ok()
    prologues.sort()

    # -- 1) sink call sites + enclosing function co-location ------------------ #
    sink_callers = _assemble_sink_callers(
        calls, prologues, sinks, srcs, filters, func_names=_func_symbol_map(elf)
    )

    # -- 2) generic GoAhead registration: (r0="form*" str, r1=code addr) ------ #
    registration: dict[str, int] = {}
    seen_sites: set[int] = set()
    str_cache: dict[int, str] = {}
    for ev in calls:
        if ev["addr"] in seen_sites:
            continue
        r0_vals = _literal_values(view, ev["window"], "r0")
        name_value: str | None = None
        for va in r0_vals:
            if not any(lo <= va < hi for lo, hi in rodata_ranges):
                continue
            text = str_cache.get(va)
            if text is None:
                text = _read_string(view, va)
                if text is not None:
                    str_cache[va] = text
            if text and _FORM_NAME_RE.match(text):
                name_value = text
                break
        if name_value is None:
            continue
        r1_vals = _literal_values(view, ev["window"], "r1")
        func_value: int | None = None
        for va in r1_vals:
            if any(lo <= va < hi for lo, hi in exec_ranges):
                func_value = va
                break
        if func_value is None and r1_vals:
            func_value = r1_vals[0]
        if name_value and func_value is not None:
            seen_sites.add(ev["addr"])
            registration[name_value] = func_value
    func_handlers = {addr: name for name, addr in registration.items()}

    return {
        "status": "ok",
        "sink_callers": sink_callers,
        "registration": registration,
        "func_handlers": func_handlers,
        "chains": _chains_from_callers(sink_callers, func_handlers),
    }


__all__ = ["SUPPORTED_ARCHES", "recover_chains", "DEFAULT_SOURCE_APIS", "DEFAULT_FILTER_APIS"]
