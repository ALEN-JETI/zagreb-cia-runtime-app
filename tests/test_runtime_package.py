from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
APP = ROOT / "zagreb_cia_runtime"


class RuntimePackageTests(unittest.TestCase):
    def test_runtime_security_profile_and_version(self) -> None:
        config = (APP / "config.yaml").read_text(encoding="utf-8")
        self.assertIn('version: "0.3.0"', config)
        self.assertIn("stdin: true", config)
        self.assertIn("host_network: false", config)
        self.assertIn("full_access: false", config)
        self.assertIn("apparmor: true", config)
        self.assertIn("ingress: false", config)
        self.assertIn("ports: {}", config)
        self.assertIn("privileged: []", config)
        self.assertIn("usb: false", config)
        self.assertIn("map: []", config)
        self.assertNotIn("hassio_api:", config)
        self.assertNotIn("homeassistant_api:", config)
        self.assertNotIn("docker_api:", config)
        self.assertIn('image: "ghcr.io/alen-jeti/zagreb-cia-runtime"', config)

    def test_runtime_start_survives_without_otbr_call(self) -> None:
        run_script = (APP / "run.sh").read_text(encoding="utf-8")
        self.assertIn("self-test=ok", run_script)
        self.assertIn("runtime=started", run_script)
        self.assertIn("exec python3 -u /cia_observer_dispatcher.py", run_script)
        self.assertNotIn("zagreb_ha_get_otbr_runtime_status", run_script)
        self.assertNotIn("zagreb_otbr_runtime_adapter.py", run_script)

    def test_build_package_contains_dispatcher_without_external_interface(self) -> None:
        dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ARG BUILD_VERSION=0.3.0", dockerfile)
        self.assertIn(
            "COPY zagreb_otbr_runtime_adapter.py /zagreb_otbr_runtime_adapter.py",
            dockerfile,
        )
        self.assertIn(
            "COPY cia_observer_dispatcher.py /cia_observer_dispatcher.py",
            dockerfile,
        )
        self.assertNotIn("EXPOSE", dockerfile)

    def test_build_workflow_is_aarch64_version_0_3_0_and_release_gated(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('VERSION: "0.3.0"', workflow)
        self.assertIn('ARCHITECTURES: \'["aarch64"]\'', workflow)
        self.assertIn("context: ./zagreb_cia_runtime", workflow)
        self.assertIn("push: ${{ github.event_name == 'release' }}", workflow)

    def test_package_text_files_use_lf_line_endings(self) -> None:
        files = [
            ROOT / ".github" / "workflows" / "build.yml",
            ROOT / "repository.yaml",
            APP / "config.yaml",
            APP / "Dockerfile",
            APP / "run.sh",
            APP / "cia_observer_dispatcher.py",
            APP / "zagreb_otbr_runtime_adapter.py",
        ]
        for path in files:
            with self.subTest(path=path):
                self.assertNotIn(b"\r\n", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
