import subprocess

from skpatch import onnode
from skpatch.config import ClusterConfig
from skpatch.imageref import parse_image_ref


class FakeSsh:
    """Records every ssh argv and answers by matching a substring of the remote command."""

    def __init__(self, answers):
        self.answers = answers  # list of (substring, returncode, stdout)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        remote = argv[-1]
        for needle, rc, out in self.answers:
            if needle in remote:
                return subprocess.CompletedProcess(argv, rc, out, "")
        return subprocess.CompletedProcess(argv, 1, "", "no answer")


def cluster(**kw):
    return ClusterConfig(manager_hosts=["mgr1", "mgr2"], **kw)


def test_locate_node_asks_the_first_reachable_manager_for_the_running_task():
    ssh = FakeSsh([("true", 0, ""), ("service ps", 0, "node-b\n")])
    assert onnode.locate_node(cluster(), "stack_svc", runner=ssh) == "node-b"
    remote = ssh.calls[-1][-1]
    assert "docker service ps stack_svc" in remote and "desired-state=running" in remote


def test_locate_node_returns_none_when_no_task_runs():
    ssh = FakeSsh([("true", 0, ""), ("service ps", 0, "\n")])
    assert onnode.locate_node(cluster(), "stack_svc", runner=ssh) is None


def test_node_host_maps_a_swarm_hostname_to_its_ssh_alias():
    c = cluster(node_hosts={"nammgr1001": "nammgr1001-ts"})
    assert onnode.node_host(c, "nammgr1001") == "nammgr1001-ts"
    assert onnode.node_host(c, "other") == "other"


def test_pin_to_local_id_adds_the_node_image_id_when_the_ref_has_no_digest():
    ssh = FakeSsh([("image inspect", 0, "sha256:abc\n")])
    ref = onnode.pin_to_local_id(
        parse_image_ref("skgentis/skgentis:420d9ea3"),
        "skgentis/skgentis:420d9ea3",
        "gen1",
        cluster(),
        runner=ssh,
    )
    assert ref.tag == "420d9ea3" and ref.digest == "sha256:abc"


def test_pin_to_local_id_keeps_an_existing_digest_without_asking():
    ssh = FakeSsh([])
    raw = "127.0.0.1:5000/w:1@sha256:def"
    ref = onnode.pin_to_local_id(parse_image_ref(raw), raw, "n1", cluster(), runner=ssh)
    assert ref.digest == "sha256:def" and ssh.calls == []


def test_trivy_runner_runs_the_pinned_trivy_container_on_the_node_against_its_docker_daemon():
    ssh = FakeSsh([("docker run", 0, '{"bomFormat": "CycloneDX"}')])
    run = onnode.trivy_runner(
        "node-b", cluster(ssh_user="u"), container_image="aquasec/trivy:1@sha256:x", runner=ssh
    )
    proc = run(
        ["trivy", "image", "--quiet", "--format", "cyclonedx", "img:1"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0 and "CycloneDX" in proc.stdout
    argv = ssh.calls[-1]
    assert "u@node-b" in argv
    remote = argv[-1]
    assert "/var/run/docker.sock:/var/run/docker.sock" in remote
    assert "--network host" in remote
    assert "aquasec/trivy:1@sha256:x image --quiet --format cyclonedx img:1" in remote


def test_trivy_runner_reports_an_unreachable_node_as_a_failed_scan():
    def down(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 255, "", "no route")

    run = onnode.trivy_runner("node-b", cluster(), container_image="t", runner=down)
    proc = run(["trivy", "image", "x"], capture_output=True, text=True, timeout=5)
    assert proc.returncode != 0 and "no route" in proc.stderr
