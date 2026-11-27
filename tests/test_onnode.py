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


def test_running_image_id_reads_the_image_of_the_services_running_container():
    ssh = FakeSsh([("docker ps", 0, "sha256:abc\n")])
    assert onnode.running_image_id("n1", cluster(), "stack_svc", runner=ssh) == "sha256:abc"
    remote = ssh.calls[-1][-1]
    assert "label=com.docker.swarm.service.name=stack_svc" in remote and "{{.Image}}" in remote


def test_running_image_id_is_none_without_a_container():
    ssh = FakeSsh([("docker ps", 1, "")])
    assert onnode.running_image_id("n1", cluster(), "stack_svc", runner=ssh) is None


def test_pin_ref_adds_the_running_id_only_to_a_tag_only_ref():
    tag_only = parse_image_ref("skgentis/skgentis:420d9ea3")
    pinned = onnode.pin_ref(tag_only, "sha256:abc")
    assert pinned.tag == "420d9ea3" and pinned.digest == "sha256:abc"
    digest_ref = parse_image_ref("127.0.0.1:5000/w:1@sha256:def")
    assert onnode.pin_ref(digest_ref, "sha256:abc").digest == "sha256:def"
    assert onnode.pin_ref(tag_only, None).digest is None


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
