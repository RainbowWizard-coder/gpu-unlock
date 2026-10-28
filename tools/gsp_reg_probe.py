#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read BAR0 registers *through GSP-RM* using the public regops control.

Why this exists: on a GSP-enabled part (Blackwell, Hopper, Ampere-with-GSP) the
host CPU is not the only bus master that can touch BAR0. RM exposes
NV2080_CTRL_CMD_GPU_EXEC_REG_OPS, which asks the server-side RM - GSP-RM on
these chips - to perform the register access on behalf of the client. Whether a
GSP-originated access is treated differently from a CPU-originated one matters
for any feature whose registers are gated by access privilege, so the two paths
have to be compared instead of assumed equal.

This tool only ever submits read operations; the opcode list is fixed and there
is no code path that can emit a write. Reads are performed as the calling user,
and RM requires CAP_SYS_ADMIN (root) for offsets outside the user-mode register
allow list, so run it as root.

Two paths are provided so results can be cross-checked:
  --via rm     GSP-RM performs the access (default).
  --via sysfs  the kernel maps BAR0 (read-only) and the CPU performs the access.
               Kernels refuse that mapping while a driver owns the device, so
               this path needs a GPU no driver has claimed.

ABI: NVIDIA open-gpu-kernel-modules; struct layouts taken from the public SDK
headers (nvos.h, ctrl2080gpu.h). Values are only checked for plausibility, the
tool never interprets them beyond the named preset registers.
"""
import argparse
import ctypes as C
import json
import os
import sys

U8, U32, U64 = C.c_uint8, C.c_uint32, C.c_uint64

# RM escape codes (nv_escape.h) and ioctl class.
ESC_RM_ALLOC = 0x2B
ESC_RM_CONTROL = 0x2A

# NV2080_CTRL_CMD_GPU_EXEC_REG_OPS (ctrl2080gpu.h).
CMD_EXEC_REG_OPS = 0x20800122

# NV2080_CTRL_GPU_REG_OP_* (ctrl2080gpu.h). Only reads are ever emitted.
REG_OP_READ_32 = 0x00
REG_OP_TYPE_GLOBAL = 0x00

# Preset register sets. Offsets are BAR0 byte offsets that are known to exist on
# the chip families named; the tool reports the raw value plus a decoded field
# only where the encoding is public (see gpu-unlock registers.h).
PRESETS = {
    "speed-select": {
        "description": "SM issue-rate selector latch, override privilege mask, "
                       "and the fuse-sampled rate words shared by Ampere..Blackwell",
        "offsets": {
            "FEAT_OVR_PLM": 0x00823804,
            "FEAT_READOUT_1": 0x00823818,
            "FEAT_SS0": 0x0082381C,
            "FEAT_SS1": 0x00823820,
            "FUSE_SS_DP": 0x00820224,
            "FUSE_FFMA": 0x0082059C,
            "FUSE_FMLA16": 0x008207D4,
            "FUSE_FMLA32": 0x008207D8,
            "FUSE_IMLA0": 0x008207DC,
            "FUSE_IMLA1": 0x008207E0,
            "FUSE_IMLA2": 0x008207E4,
            "FUSE_IMLA3": 0x008207E8,
            "FUSE_IMLA4": 0x008207EC,
            "PMC_BOOT_0": 0x00000000,
        },
    },
}


class Alloc(C.Structure):
    """NVOS64_PARAMETERS (nvos.h)."""
    _fields_ = [(name, U32) for name in ("root", "parent", "new", "cls")] + [
        ("params", U64), ("rights", U64), ("size", U32),
        ("flags", U32), ("status", U32)]


class Control(C.Structure):
    """NVOS54_PARAMETERS (nvos.h)."""
    _fields_ = [(name, U32) for name in ("client", "obj", "cmd", "flags")] + [
        ("params", U64), ("size", U32), ("status", U32)]


class Device(C.Structure):
    """NV0080_ALLOC_PARAMETERS (cl0080.h)."""
    _fields_ = [(name, U32) for name in ("device", "share", "target_client",
                                         "target_device", "flags")] + [
        ("va_size", U64), ("va_start", U64), ("va_limit", U64), ("va_mode", U32)]


class RegOp(C.Structure):
    """NV2080_CTRL_GPU_REG_OP (ctrl2080gpu.h)."""
    _fields_ = [("reg_op", U8), ("reg_type", U8), ("reg_status", U8),
                ("reg_quad", U8), ("group_mask", U32), ("sub_group_mask", U32),
                ("offset", U32), ("value_hi", U32), ("value_lo", U32),
                ("andn_mask_hi", U32), ("andn_mask_lo", U32)]


class RegOpsParams(C.Structure):
    """NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS (ctrl2080gpu.h)."""
    _fields_ = [("client_target", U32), ("channel_target", U32),
                ("non_transactional", U32), ("reserved00", U32 * 2),
                ("reg_op_count", U32), ("reg_ops", U64),
                ("route_flags", U32), ("route_size", U32), ("route", U64)]


assert C.sizeof(Alloc) == 48 and C.sizeof(Control) == 32
assert C.sizeof(Device) == 56 and C.sizeof(RegOp) == 32
assert C.sizeof(RegOpsParams) == 48 and RegOpsParams.reg_ops.offset == 24

# regStatus bits (ctrl2080gpu.h).
STATUS_BITS = {0x01: "invalid_op", 0x02: "invalid_type", 0x04: "invalid_offset",
               0x08: "unsupported_op", 0x10: "invalid_mask", 0x20: "noaccess"}


def ioctl_number(number, structure):
    return (3 << 30) | (C.sizeof(structure) << 16) | (ord("F") << 8) | number


def resolve_ioctl(ioctl):
    if ioctl is not None:
        return ioctl
    import fcntl
    return fcntl.ioctl


def call_ioctl(fd, number, structure, ioctl):
    buffer = bytearray(bytes(structure))
    ioctl(fd, number, buffer, True)
    C.memmove(C.addressof(structure), bytes(buffer), len(buffer))
    if structure.status:
        raise RuntimeError(f"RM request failed with status "
                           f"0x{structure.status:x}")


def rm_session(use, ioctl=None):
    """Open temporary RM handles and pass (ctl, client, subdevice) to `use`."""
    ioctl = resolve_ioctl(ioctl)
    descriptors = []
    try:
        open_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        ctl = os.open("/dev/nvidiactl", open_flags)
        descriptors.append(ctl)
        descriptors.append(os.open("/dev/nvidia0", open_flags))

        def allocate(root, parent, cls, params=None):
            request = Alloc(root=root, parent=parent, cls=cls,
                            params=C.addressof(params) if params is not None else 0,
                            size=C.sizeof(params) if params is not None else 0)
            call_ioctl(ctl, ioctl_number(ESC_RM_ALLOC, Alloc), request, ioctl)
            if not request.new:
                raise RuntimeError("RM returned an empty object handle")
            return request.new

        client = allocate(0, 0, 0x41)
        device = allocate(client, client, 0x80, Device())
        subdevice = allocate(client, device, 0x2080, U32(0))
        return use(ctl, client, subdevice)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_via_rm(offsets, ioctl=None):
    """Ask GSP-RM to read every offset; returns {offset: value}."""
    ioctl = resolve_ioctl(ioctl)

    def use(ctl, client, subdevice):
        ops = (RegOp * len(offsets))()
        for index, offset in enumerate(offsets):
            ops[index].reg_op = REG_OP_READ_32
            ops[index].reg_type = REG_OP_TYPE_GLOBAL
            ops[index].offset = offset
        params = RegOpsParams(client_target=0, channel_target=0,
                              non_transactional=1, reg_op_count=len(offsets),
                              reg_ops=C.addressof(ops))
        request = Control(client=client, obj=subdevice, cmd=CMD_EXEC_REG_OPS,
                          params=C.addressof(params), size=C.sizeof(params))
        call_ioctl(ctl, ioctl_number(ESC_RM_CONTROL, Control), request, ioctl)

        results = {}
        for index, offset in enumerate(offsets):
            status = ops[index].reg_status
            if status:
                reasons = "|".join(name for bit, name in STATUS_BITS.items()
                                   if status & bit) or f"0x{status:x}"
                results[offset] = {"error": reasons}
            else:
                results[offset] = {"value": ops[index].value_lo}
        return results

    return rm_session(use, ioctl)


def read_via_sysfs(pci_slot, offsets):
    """Map BAR0 read-only and read from the CPU; returns {offset: value}.

    Only a PROT_READ mapping is created, so this path cannot write even
    accidentally. Comparing it against `read_via_rm` shows whether an offset
    behaves differently for the CPU and for the device-side master.
    """
    import mmap
    path = f"/sys/bus/pci/devices/{pci_slot}/resource0"
    size = os.path.getsize(path)
    descriptor = os.open(path, os.O_RDWR | os.O_SYNC)
    try:
        region = mmap.mmap(descriptor, size, mmap.MAP_SHARED, mmap.PROT_READ)
        try:
            return {offset: {"value": C.get_uint32(region, offset)}
                    for offset in offsets}
        finally:
            region.close()
    finally:
        os.close(descriptor)


def probe(preset=None, offsets=None, via="rm", pci_slot=None, nvidia_smi="nvidia-smi"):
    named = {}
    if preset:
        named = dict(PRESETS[preset]["offsets"])
    for offset in offsets or []:
        named.setdefault(f"0x{offset:08x}", offset)
    if not named:
        raise SystemExit("nothing to read: pass --preset or --offset")
    order = list(named)
    unique = sorted(set(named.values()))
    if via == "rm":
        results = read_via_rm(unique)
    else:
        results = read_via_sysfs(pci_slot, unique)
    values = {}
    for name, offset in named.items():
        entry = results[offset]
        values[name] = {"offset": f"0x{offset:08x}"}
        values[name].update({"value": f"0x{entry['value']:08x}"} if "value" in entry
                            else {"error": entry["error"]})
    return {"via": via, "preset": preset, "command": f"0x{CMD_EXEC_REG_OPS:x}",
            "results": values}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--preset", choices=sorted(PRESETS))
    parser.add_argument("--offset", type=lambda s: int(s, 0), action="append",
                        help="additional BAR0 offset, repeatable")
    parser.add_argument("--via", choices=("rm", "sysfs"), default="rm",
                        help="rm: GSP-RM performs the access; sysfs: CPU performs it "
                             "(needs an unused device - kernels refuse to map BAR0 "
                             "while a driver owns it)")
    parser.add_argument("--pci-slot", default="0000:01:00.0")
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.preset, args.offset, args.via, args.pci_slot),
                         indent=2))
    except PermissionError:
        print("this tool needs CAP_SYS_ADMIN for most offsets; run it as root",
              file=sys.stderr)
        return 1
    except OSError as error:
        hint = (" - the kernel will not map BAR0 while a driver owns the device; "
                "use --via rm for a bound GPU"
                if args.via == "sysfs" else "")
        print(f"{error}{hint}", file=sys.stderr)
        return 1
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
