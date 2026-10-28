# SPDX-License-Identifier: GPL-2.0-only
"""Layout and read-only guarantees of tools/gsp_reg_probe.py.

No GPU, no root and no driver ioctl are touched: the ioctl is replaced by a
recording stand-in, which is also how the submitted register operations are
inspected.
"""
import ctypes as C
import importlib.util
from pathlib import Path
from unittest import TestCase, mock

TOOL = Path(__file__).resolve().parents[1] / "tools/gsp_reg_probe.py"
spec = importlib.util.spec_from_file_location("gsp_reg_probe", TOOL)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def recorded_ioctls(status=(), values=()):
    """Run read_via_rm against a stand-in ioctl, recording every register op.

    Field values are copied out as plain integers while the caller's buffers are
    still alive; a ctypes struct view would outlive them and read back zeros.
    """
    submitted = {}
    calls = []

    def ioctl(fd, code, buffer, mutate):
        calls.append(code)
        if code == probe.ioctl_number(0x2B, probe.Alloc):
            probe.Alloc.from_buffer(buffer).new = 100 + len(calls)
            return
        request = probe.Control.from_buffer(buffer)
        params = C.cast(request.params, C.POINTER(probe.RegOpsParams)).contents
        ops = C.cast(C.c_void_p(params.reg_ops),
                     C.POINTER(probe.RegOp * params.reg_op_count)).contents
        submitted.update(cmd=request.cmd,
                         client_target=params.client_target,
                         channel_target=params.channel_target,
                         non_transactional=params.non_transactional,
                         reg_op_count=params.reg_op_count,
                         ops=[(op.reg_op, op.reg_type, op.offset, op.value_hi,
                               op.value_lo, op.andn_mask_hi, op.andn_mask_lo)
                              for op in ops])
        for index, value in enumerate(values):
            ops[index].value_lo = value
        for index, bit in status:
            ops[index].reg_status |= bit

    with mock.patch.object(probe.os, "open", side_effect=[7, 8]), \
         mock.patch.object(probe.os, "close") as close:
        results = probe.read_via_rm([0x823804, 0x82381c], ioctl)
    return results, submitted, calls, close


class GspRegProbeTests(TestCase):
    def test_abi_layouts_and_ioctl_numbers(self):
        self.assertEqual([C.sizeof(s) for s in (probe.Alloc, probe.Control,
                                                probe.Device, probe.RegOp,
                                                probe.RegOpsParams)],
                         [48, 32, 56, 32, 48])
        self.assertEqual(probe.RegOpsParams.reg_ops.offset, 24)
        self.assertEqual([getattr(probe.RegOp, name).offset for name in
                          ("offset", "value_hi", "value_lo", "andn_mask_hi",
                           "andn_mask_lo")],
                         [0xc, 0x10, 0x14, 0x18, 0x1c])
        self.assertEqual(probe.ioctl_number(0x2B, probe.Alloc), 0xC030462B)
        self.assertEqual(probe.ioctl_number(0x2A, probe.Control), 0xC020462A)

    def test_three_handles_then_the_regops_control(self):
        _, submitted, calls, close = recorded_ioctls(values=(0xfffffb8f, 0))
        alloc = probe.ioctl_number(0x2B, probe.Alloc)
        self.assertEqual(calls, [alloc, alloc, alloc,
                                 probe.ioctl_number(0x2A, probe.Control)])
        self.assertEqual(submitted["cmd"], probe.CMD_EXEC_REG_OPS)
        self.assertEqual(close.call_args_list, [mock.call(8), mock.call(7)])

    def test_every_submitted_operation_is_a_read(self):
        _, submitted, _, _ = recorded_ioctls(values=(0xfffffb8f, 0x31066057))
        self.assertEqual([op[0] for op in submitted["ops"]],
                         [probe.REG_OP_READ_32] * 2)
        self.assertEqual([op[1] for op in submitted["ops"]],
                         [probe.REG_OP_TYPE_GLOBAL] * 2)
        self.assertEqual([op[2] for op in submitted["ops"]],
                         [0x823804, 0x82381c])
        # A read must leave the write operands alone: with a zero AND-mask and a
        # zero OR-value, a WRITE opcode would be a no-op rather than obviously
        # harmless, so the mask/value are asserted as well as the opcode.
        for op in submitted["ops"]:
            self.assertEqual((op[3], op[4]), (0, 0))
            self.assertEqual((op[5], op[6]), (0, 0))

    def test_targets_stay_zero(self):
        # hClientTarget and hChannelTarget must both be 0 or both be a real
        # channel; passing a client handle as the channel fails 0x40.
        _, submitted, _, _ = recorded_ioctls()
        self.assertEqual((submitted["client_target"],
                          submitted["channel_target"]), (0, 0))
        self.assertEqual(submitted["non_transactional"], 1)
        self.assertEqual(submitted["reg_op_count"], 2)

    def test_per_operation_status_bits_are_decoded(self):
        results, _, _, _ = recorded_ioctls(status=[(1, 0x20)], values=(0x42, 0))
        self.assertEqual(results[0x823804], {"value": 0x42})
        self.assertEqual(results[0x82381c], {"error": "noaccess"})

    def test_rejected_control_still_closes_both_descriptors(self):
        def ioctl(fd, code, buffer, mutate):
            if code == probe.ioctl_number(0x2B, probe.Alloc):
                probe.Alloc.from_buffer(buffer).new = 1
            else:
                probe.Control.from_buffer(buffer).status = 0x1f

        with mock.patch.object(probe.os, "open", side_effect=[7, 8]), \
             mock.patch.object(probe.os, "close") as close:
            with self.assertRaisesRegex(RuntimeError, "status 0x1f"):
                probe.read_via_rm([0x823804], ioctl)
        self.assertEqual(close.call_args_list, [mock.call(8), mock.call(7)])

    def test_source_offers_no_write_opcode_or_writable_mapping(self):
        text = TOOL.read_text()
        for forbidden in ("REG_OP_WRITE", "PROT_WRITE", "mmap.PROT_WRITE"):
            self.assertNotIn(forbidden, text)
