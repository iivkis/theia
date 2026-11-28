import importlib.util
from copy import deepcopy
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "ci-native-targets.py"
spec = importlib.util.spec_from_file_location("ci_native_targets", SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def metadata():
    return {"workspace_members": ["app"], "packages": [{
        "id": "app",
        "targets": [{"name": "app", "kind": ["lib"]},
                    {"name": "app", "kind": ["bin"]},
                    {"name": "net", "kind": ["test"]},
                    {"name": "cli", "kind": ["test"]},
                    {"name": "build-script", "kind": ["custom-build"]}],
    }]}


class NativeTargetsTests(unittest.TestCase):
    def test_exact_disjoint_target_groups(self):
        value = metadata()
        grouped = native.groups(value)
        self.assertEqual(set(grouped["unit"]), {("app", "lib", "app"), ("app", "bin", "app")})
        self.assertEqual(set(grouped["integration"]), {("app", "test", "net"), ("app", "test", "cli")})
        value["packages"][0]["targets"].append({"name": "new", "kind": ["test"]})
        self.assertIn(("app", "test", "new"), native.groups(value)["integration"])

    def test_unknown_targets_and_incomplete_workspace_fail_closed(self):
        for kind in ("bench", "example", "proc-macro"):
            value = metadata()
            value["packages"][0]["targets"].append({"name": "unassigned", "kind": [kind]})
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                native.groups(value)
        for mutation in ("duplicate", "missing-member", "empty-group", "wrong-shape"):
            value = deepcopy(metadata())
            if mutation == "duplicate":
                value["packages"][0]["targets"].append(value["packages"][0]["targets"][0])
            elif mutation == "missing-member":
                value["workspace_members"].append("missing")
            elif mutation == "empty-group":
                value["packages"][0]["targets"] = value["packages"][0]["targets"][:2]
            else:
                value["packages"][0]["targets"][0]["kind"] = ["lib", "bin"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                native.groups(value)


if __name__ == "__main__":
    unittest.main()
