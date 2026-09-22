import unittest
from zagreb_cia_runtime import zagreb_otbr_runtime_adapter as adapter
from zagreb_cia_runtime.cia_observer_dispatcher import _is_valid_result
from test_otbr_runtime_adapter import active_payload, NOW


class StateFieldTests(unittest.TestCase):
    def test_node_state_with_empty_inventory_role(self):
        for state in ("child", "router", "leader"):
            with self.subTest(state=state):
                data = active_payload()
                data.update(state=state, role="")
                result = adapter._evaluate_node(data, now=NOW)
                self.assertEqual(result["check_status"], "OK")
                self.assertEqual(result["border_router_active"], "TRUE")
                self.assertTrue(_is_valid_result(result))

    def test_node_state_without_inventory_role(self):
        data = active_payload()
        del data["role"]
        data["state"] = "leader"
        self.assertEqual(adapter._evaluate_node(data, now=NOW)["border_router_active"], "TRUE")

    def test_inactive_node_is_never_overridden_by_inventory(self):
        for state in ("disabled", "detached"):
            data = active_payload()
            data.update(state=state, role="")
            result = adapter._evaluate_node(data, now=NOW)
            self.assertEqual(result["border_router_active"], "FALSE")
            self.assertEqual(result["routing_ready"], "FALSE")

    def test_conflicting_fields_fail_closed(self):
        for state, role in (("detached", "leader"), ("leader", "detached"),
                            ("router", "child"), ("leader", "future-role")):
            data = active_payload()
            data.update(state=state, role=role)
            result = adapter._evaluate_node(data, now=NOW)
            self.assertEqual(result["check_status"], "UNKNOWN")
            self.assertEqual(result["routing_ready"], "UNKNOWN")
            self.assertTrue(_is_valid_result(result))

    def test_invalid_or_unknown_present_state_does_not_fall_back(self):
        for state in (None, True, 1, "", "future-state", [], {}):
            data = active_payload()
            data["state"] = state
            result = adapter._evaluate_node(data, now=NOW)
            self.assertEqual(result["check_status"], "UNKNOWN")
            self.assertEqual(result["border_router_active"], "UNKNOWN")

    def test_matching_fields_and_whitespace(self):
        data = active_payload()
        data.update(state=" Leader ", role="leader")
        self.assertEqual(adapter._evaluate_node(data, now=NOW)["check_status"], "OK")

    def test_missing_routing_data_remains_unknown(self):
        data = {"state": "leader", "role": ""}
        result = adapter._evaluate_node(data, now=NOW)
        self.assertEqual(result["border_router_active"], "TRUE")
        self.assertEqual(result["routing_ready"], "UNKNOWN")

    def test_output_does_not_expose_field_values(self):
        data = active_payload()
        data.update(state="private-secret-state", role="")
        result = adapter._evaluate_node(data, now=NOW)
        self.assertNotIn("private-secret", str(result))
        self.assertEqual(len(result), 6)


if __name__ == "__main__":
    unittest.main()
