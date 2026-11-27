#!/usr/bin/env python3
"""P217 negative tests; synthetic Dalvik records only, no phone or real data."""
import unittest

from audit_signed_node_bootstrap import Denied
from p216_activity_result_contracts import MAIN, LAUNCHER, CONTRACT_ROOT
from p217_main_launcher_lineage import (
    operand_regs, trace_method, inspect_dexes,
)

class I:
    def __init__(self, name, output):
        self.name, self.output = name, output
    def get_name(self):
        return self.name
    def get_output(self):
        return self.output

class Field:
    def __init__(self, name, desc=LAUNCHER):
        self.name, self.desc = name, desc
    def get_name(self):
        return self.name
    def get_descriptor(self):
        return self.desc

class Method:
    def __init__(self, name, rows):
        self.name, self.rows = name, rows
    def get_name(self):
        return self.name
    def get_code(self):
        return object()
    def get_instructions_idx(self):
        return self.rows

class Cls:
    def __init__(self, name, methods=(), fields=()):
        self.name, self.methods, self.fields = name, methods, fields
    def get_name(self):
        return self.name
    def get_methods(self):
        return self.methods
    def get_fields(self):
        return self.fields

class Dex:
    def __init__(self, classes):
        self.classes = classes
    def get_classes(self):
        return self.classes

PERM_ONE = CONTRACT_ROOT + "RequestPermission;"
PERM_MULTI = CONTRACT_ROOT + "RequestMultiplePermissions;"
OTHER = CONTRACT_ROOT + "GetContent;"
FIELD = MAIN + "->privateLauncher " + LAUNCHER
REGISTER = ("v0, v1, v2, Landroidx/activity/ComponentActivity;->"
            "registerForActivityResult(Landroidx/activity/result/contract/ActivityResultContract;"
            "Landroidx/activity/result/ActivityResultCallback;)"
            + LAUNCHER)
LAUNCH = ("v4, v5, Landroidx/activity/result/ActivityResultLauncher;"
          "->launch(Ljava/lang/Object;)V")

def setup(contract=PERM_ONE):
    return [
        (0, I("new-instance", "v1, " + contract)),
        (4, I("invoke-direct", "v1, " + contract + "-><init>()V")),
        (10, I("invoke-virtual", REGISTER)),
        (16, I("move-result-object", "v3")),
        (18, I("iput-object", "v3, v0, " + FIELD)),
    ]

def launch(with_get=True, extra=()):
    rows = [(0, I("iget-object", "v4, v0, " + FIELD))] if with_get else []
    rows.extend(extra)
    rows.append((40, I("invoke-virtual", LAUNCH)))
    return rows

class P217Tests(unittest.TestCase):
    def test_register_parse_exact_regs(self):
        self.assertEqual(operand_regs(I("invoke-virtual", REGISTER)),
                         ("v0", "v1", "v2"))
    def test_range_not_claimed(self):
        self.assertEqual(operand_regs(I("invoke-virtual/range",
                         "v0 .. v2, Landroidx/activity/X;->f()V")), ())
    def test_non_register_operand_fail_closed(self):
        self.assertEqual(operand_regs(I("invoke-virtual",
                         "v0, p1, Landroidx/activity/X;->f()V")), ())
    def test_single_permission_register_field(self):
        assigned, _ = trace_method(setup(), {"privateLauncher": 1})
        self.assertEqual(assigned, [(1, "REQUEST_ONE")])
    def test_multiple_permission_register_field(self):
        assigned, _ = trace_method(setup(PERM_MULTI), {"privateLauncher": 1})
        self.assertEqual(assigned, [(1, "REQUEST_MULTIPLE")])
    def test_non_permission_contract_stays_non_permission(self):
        assigned, _ = trace_method(setup(OTHER), {"privateLauncher": 1})
        self.assertEqual(assigned, [(1, "GET_CONTENT")])
    def test_exact_launcher_receiver_field(self):
        _, calls = trace_method(launch(), {"privateLauncher": 1})
        self.assertEqual(calls, [(40, 1)])
    def test_receiver_overwrite_is_unknown(self):
        _, calls = trace_method(launch(extra=[
            (4, I("move-object", "v4, v8"))]), {"privateLauncher": 1})
        self.assertEqual(calls, [(40, None)])
    def test_branch_invalidates_lineage(self):
        _, calls = trace_method(launch(extra=[
            (4, I("if-eqz", "v3, +4"))]), {"privateLauncher": 1})
        self.assertEqual(calls, [(40, None)])
    def test_copy_alias_keeps_field(self):
        rows = [(0, I("iget-object", "v6, v0, " + FIELD)),
                (4, I("move-object", "v4, v6")),
                (40, I("invoke-virtual", LAUNCH))]
        self.assertEqual(trace_method(rows, {"privateLauncher": 2})[1], [(40, 2)])
    def test_other_receiver_not_nearest_get(self):
        different = LAUNCH.replace("v4, v5", "v8, v5")
        rows = [(0, I("iget-object", "v4, v0, " + FIELD)),
                (40, I("invoke-virtual", different))]
        self.assertEqual(trace_method(rows, {"privateLauncher": 1})[1],
                         [(40, None)])
    def test_registration_without_result_is_unknown(self):
        rows = setup()
        rows.pop(3)
        self.assertEqual(trace_method(rows, {"privateLauncher": 1})[0],
                         [(1, "UNKNOWN")])
    def test_registration_with_uninitialized_contract_unknown(self):
        rows = setup()
        rows.pop(1)
        self.assertEqual(trace_method(rows, {"privateLauncher": 1})[0],
                         [(1, "UNKNOWN")])
    def test_registration_contract_overwritten_unknown(self):
        rows = setup()
        rows.insert(2, (6, I("const/4", "v1, 0")))
        self.assertEqual(trace_method(rows, {"privateLauncher": 1})[0],
                         [(1, "UNKNOWN")])
    def test_unknown_opcode_avoids_false_alias(self):
        _, calls = trace_method(launch(extra=[
            (4, I("nonstandard-reg-mutate", "v4, v0"))]),
            {"privateLauncher": 1})
        self.assertEqual(calls, [(40, None)])
    def test_missing_main_fail_closed(self):
        with self.assertRaises(Denied):
            inspect_dexes([("classes.dex", Dex([Cls("Lother/Main;")]))])
    def test_duplicate_main_fail_closed(self):
        fields = [Field(str(i)) for i in range(4)]
        with self.assertRaises(Denied):
            inspect_dexes([("classes.dex", Dex([
                Cls(MAIN, fields=fields), Cls(MAIN, fields=fields)]))])
    def test_static_four_launch_inventory_and_unknown(self):
        fields = [Field("a"), Field("b"), Field("c"), Field("d")]
        rows = [(0, I("iget-object",
                      "v4, v0, " + MAIN + "->a " + LAUNCHER)),
                (4, I("invoke-virtual", LAUNCH)),
                (8, I("iget-object",
                      "v4, v0, " + MAIN + "->b " + LAUNCHER)),
                (12, I("invoke-virtual", LAUNCH)),
                (16, I("iget-object",
                       "v4, v0, " + MAIN + "->c " + LAUNCHER)),
                (20, I("invoke-virtual", LAUNCH)),
                (24, I("iget-object",
                       "v4, v0, " + MAIN + "->d " + LAUNCHER)),
                (28, I("invoke-virtual", LAUNCH))]
        result = inspect_dexes([("classes.dex", Dex([
            Cls(MAIN, [Method("four", rows)], fields)]))])
        self.assertEqual(len(result[2]), 4)
        self.assertTrue(all(x == "UNKNOWN" for x in result[1].values()))
    def test_type_field_without_constructor_never_permission(self):
        rows = [(0, I("invoke-virtual", REGISTER)),
                (4, I("move-result-object", "v3")),
                (6, I("iput-object", "v3, v0, " + FIELD))]
        assigned, _ = trace_method(rows, {"privateLauncher": 1})
        self.assertEqual(assigned, [(1, "UNKNOWN")])

if __name__ == "__main__":
    unittest.main(verbosity=2)
