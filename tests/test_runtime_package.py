from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
APP = ROOT / "zagreb_cia_runtime"


def test_runtime_security_profile_and_version() -> None:
    config = (APP / "config.yaml").read_text(encoding="utf-8")
    assert 'version: "0.2.0"' in config
    assert "host_network: false" in config
    assert "full_access: false" in config
    assert "apparmor: true" in config
    assert "ingress: false" in config
    assert "ports: {}" in config
    assert "privileged: []" in config
    assert "usb: false" in config
    assert "map: []" in config
    assert "hassio_api:" not in config
    assert "homeassistant_api:" not in config
    assert "docker_api:" not in config
    assert 'image: "ghcr.io/alen-jeti/zagreb-cia-runtime"' in config


def test_skeleton_start_survives_without_otbr_call() -> None:
    run_script = (APP / "run.sh").read_text(encoding="utf-8")
    assert "self-test=ok" in run_script
    assert "runtime=started" in run_script
    assert "while true" in run_script
    assert "zagreb_ha_get_otbr_runtime_status" not in run_script
    assert "zagreb_otbr_runtime_adapter.py" not in run_script


def test_build_package_contains_adapter_without_external_interface() -> None:
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG BUILD_VERSION=0.2.0" in dockerfile
    assert "COPY zagreb_otbr_runtime_adapter.py /zagreb_otbr_runtime_adapter.py" in dockerfile
    assert "EXPOSE" not in dockerfile


def test_build_workflow_is_aarch64_version_0_2_0_and_release_gated() -> None:
    workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    assert "VERSION: \"0.2.0\"" in workflow
    assert "ARCHITECTURES: '[\"aarch64\"]'" in workflow
    assert "context: ./zagreb_cia_runtime" in workflow
    assert "push: ${{ github.event_name == 'release' }}" in workflow


def test_package_text_files_use_lf_line_endings() -> None:
    files = [
        ROOT / ".github" / "workflows" / "build.yml",
        ROOT / "repository.yaml",
        APP / "config.yaml",
        APP / "Dockerfile",
        APP / "run.sh",
        APP / "zagreb_otbr_runtime_adapter.py",
    ]
    for path in files:
        assert b"\r\n" not in path.read_bytes(), path
