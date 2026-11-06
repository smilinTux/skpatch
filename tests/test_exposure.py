"""exposure.classify_exposure must tell apart a forward-auth (SSO) gate, a
public router with no forward-auth (WAF-only or native app login - either
way unauthenticated requests reach app code), and a service with no public
router at all - without crashing on odd label shapes."""

import subprocess

from skpatch.exposure import classify_exposure, fetch_service_labels


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_forward_auth_middleware_is_sso_gated():
    labels = {
        "traefik.http.routers.skhome.rule": "Host(`skhome.example.org`)",
        "traefik.http.routers.skhome.middlewares": "default-no-error-pages@file,authentik@file",
    }
    result = classify_exposure(labels)
    assert result.exposure == "sso"
    assert "authentik" in result.mechanism


def test_public_router_without_forward_auth_is_public():
    labels = {
        "traefik.http.routers.skbook.rule": "Host(`skbook.example.org`)",
        "traefik.http.routers.skbook.middlewares": "waf-bouncer@file,default-no-waf@file",
    }
    result = classify_exposure(labels)
    assert result.exposure == "public"


def test_no_public_rule_is_internal():
    labels = {"traefik.http.routers.internal.middlewares": "default@file"}
    result = classify_exposure(labels)
    assert result.exposure == "internal"


def test_no_traefik_labels_at_all_is_internal():
    assert classify_exposure({}).exposure == "internal"
    assert classify_exposure({"com.docker.stack.namespace": "some-stack"}).exposure == "internal"


def test_public_router_with_no_middleware_label_is_public():
    labels = {"traefik.http.routers.skmesh.rule": "Host(`skmesh.example.org`)"}
    assert classify_exposure(labels).exposure == "public"


def test_fetch_service_labels_handles_unreachable_and_bad_json():
    def unreachable_runner(argv, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    assert fetch_service_labels("svc", manager="mgr1", runner=unreachable_runner) == {}

    def bad_json_runner(argv, capture_output, text, timeout):
        return FakeCompleted(0, stdout="not json")

    assert fetch_service_labels("svc", manager="mgr1", runner=bad_json_runner) == {}

    def happy_runner(argv, capture_output, text, timeout):
        return FakeCompleted(0, stdout='{"traefik.enable": "true"}')

    assert fetch_service_labels("svc", manager="mgr1", runner=happy_runner) == {"traefik.enable": "true"}
