"""probe.probe_runtime must find the node a service's task is actually
running on and exec the probe there without ever raising (a container with
no matching runtime or an unreachable node comes back as a ProbeResult
error, since one bad probe must not take down the whole fleet run), and
probe.evaluate must flag a version below its configured floor without
crashing on a probe that produced no usable version."""

import subprocess

from skpatch.probe import default_floors_path, evaluate, load_floors, probe_runtime, runtimes_for_image

FLOORS = {
    "php": {
        "images": ["nextcloud", "linuxserver/bookstack", "windmill-labs/windmill"],
        "probe": ["php", "-r", "echo PHP_VERSION;"],
        "parse": r"(\d+\.\d+\.\d+)",
        "min_versions": {"8.5": 12, "8.4": 27, "8.3": 36, "8.2": 35},
    }
}


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_happy_path_finds_node_container_and_probes_it():
    def fake_runner(argv, capture_output, text, timeout):
        cmd = argv[-1]
        if "service ps" in cmd:
            return FakeCompleted(0, stdout="mgr3\n")
        if "docker ps" in cmd:
            return FakeCompleted(0, stdout="a298d0a6b4ed\n")
        if "docker exec" in cmd:
            return FakeCompleted(0, stdout="8.5.11")
        raise AssertionError(cmd)

    result = probe_runtime(
        "estate-prod_nextcloud",
        ["php", "-r", "echo PHP_VERSION;"],
        manager="mgr1",
        jump=None,
        user=None,
        identity=None,
        runner=fake_runner,
    )
    assert result.error is None
    assert result.output == "8.5.11"


def test_no_running_task_is_an_error_not_a_crash():
    def fake_runner(argv, capture_output, text, timeout):
        return FakeCompleted(0, stdout="")  # service ps finds nothing running

    result = probe_runtime(
        "estate-prod_bookstack",
        ["php", "-r", "echo PHP_VERSION;"],
        manager="mgr1",
        jump=None,
        user=None,
        identity=None,
        runner=fake_runner,
    )
    assert result.output is None
    assert "no running task" in result.error


def test_container_without_the_probed_runtime_is_an_error_not_a_crash():
    def fake_runner(argv, capture_output, text, timeout):
        cmd = argv[-1]
        if "service ps" in cmd:
            return FakeCompleted(0, stdout="worker1\n")
        if "docker ps" in cmd:
            return FakeCompleted(0, stdout="7ae6fbc6f9a1\n")
        if "docker exec" in cmd:
            return FakeCompleted(
                126, stderr='OCI runtime exec failed: exec: "php": executable file not found'
            )
        raise AssertionError(cmd)

    result = probe_runtime(
        "estate-prod_worker",
        ["php", "-r", "echo PHP_VERSION;"],
        manager="mgrB1",
        jump="jumphost",
        user="deployuser",
        identity="~/.ssh/deploy_key",
        runner=fake_runner,
    )
    assert result.output is None
    assert "not found" in result.error


def test_node_unreachable_is_an_error_not_a_crash():
    def fake_runner(argv, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    result = probe_runtime(
        "estate-prod_nextcloud",
        ["php", "-r", "echo PHP_VERSION;"],
        manager="mgr1",
        jump=None,
        user=None,
        identity=None,
        runner=fake_runner,
    )
    assert result.output is None
    assert result.error


def test_below_floor_is_flagged():
    check = evaluate("php", FLOORS, "8.5.10")
    assert check.below_floor
    assert check.floor == 12
    assert check.version == "8.5.10"


def test_at_floor_is_not_flagged():
    check = evaluate("php", FLOORS, "8.5.12")
    assert not check.below_floor


def test_probe_failure_does_not_crash_and_is_not_flagged():
    check = evaluate("php", FLOORS, None, probe_error='OCI runtime exec failed: exec: "php": not found')
    assert not check.below_floor
    assert "probe failed" in check.note


def test_unconfigured_minor_line_is_informational_not_a_failure():
    check = evaluate("php", FLOORS, "8.6.1")
    assert not check.below_floor
    assert "no floor configured" in check.note


def test_runtimes_for_image_matches_by_substring():
    assert runtimes_for_image(FLOORS, "linuxserver/bookstack") == ["php"]
    assert runtimes_for_image(FLOORS, "redis") == []


def test_bundled_floors_file_loads_and_matches_php():
    floors = load_floors(default_floors_path())
    assert "php" in floors
    assert runtimes_for_image(floors, "nextcloud") == ["php"]
