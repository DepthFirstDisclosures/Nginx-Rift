import unittest
import pathlib
import sys
import contextlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import nginx_rift_k8s_scan as scan


@contextlib.contextmanager
def patched_attr(module, name, replacement):
    original = getattr(module, name)
    setattr(module, name, replacement)
    try:
        yield
    finally:
        setattr(module, name, original)


class RewriteParserTests(unittest.TestCase):
    def test_detects_public_poc_nginx_config(self):
        poc_config = pathlib.Path(__file__).resolve().parents[1] / "env" / "nginx.conf"

        findings = scan.scan_nginx_config(poc_config.read_text())

        self.assertEqual(findings.rewrite_total, 1)
        self.assertEqual(findings.set_total, 1)
        self.assertEqual(len(findings.rewrite_question), 1)
        self.assertEqual(findings.rewrite_question[0].line, 40)
        self.assertEqual(findings.rewrite_question[0].regex, "^/api/(.*)$")
        self.assertEqual(findings.rewrite_question[0].replacement, "/internal?migrated=true")

    def test_does_not_trigger_when_public_poc_rewrite_question_is_removed(self):
        poc_config = pathlib.Path(__file__).resolve().parents[1] / "env" / "nginx.conf"
        safe_config = poc_config.read_text().replace(
            "/internal?migrated=true",
            "/internal/migrated-true",
        )

        findings = scan.scan_nginx_config(safe_config)

        self.assertEqual(findings.rewrite_total, 1)
        self.assertEqual(findings.set_total, 1)
        self.assertEqual(findings.rewrite_question, [])

    def test_finds_rewrite_replacement_with_literal_question(self):
        config = """
        location ~ ^/api/(.*)$ {
            rewrite ^/api/(.*)$ /internal?migrated=true;
            set $original_endpoint $1;
        }
        """

        findings = scan.scan_nginx_config(config)

        self.assertEqual(len(findings.rewrite_question), 1)
        self.assertEqual(findings.rewrite_question[0].line, 3)
        self.assertEqual(findings.rewrite_question[0].replacement, "/internal?migrated=true")

    def test_ignores_question_mark_in_regex_token(self):
        config = """
        rewrite ^/api/(?:v1|v2)/(.*)$ /internal/$1 last;
        """

        findings = scan.scan_nginx_config(config)

        self.assertEqual(findings.rewrite_total, 1)
        self.assertEqual(findings.rewrite_question, [])

    def test_parses_quoted_replacement(self):
        config = 'rewrite ^/x/(.*)$ "/internal?migrated=true" break;'

        findings = scan.scan_nginx_config(config)

        self.assertEqual(len(findings.rewrite_question), 1)
        self.assertEqual(findings.rewrite_question[0].replacement, "/internal?migrated=true")

    def test_handles_inline_comments_tabs_and_multiple_rewrites(self):
        config = """
	    rewrite   ^/safe/(.*)$   /safe/$1   last; # regex and replacement are safe
	    rewrite	^/risky/(.*)$	"/internal?from=risky"	break; # should be flagged
            set $captured $1; # counted but not required for the trigger primitive
        """

        findings = scan.scan_nginx_config(config)

        self.assertEqual(findings.rewrite_total, 2)
        self.assertEqual(findings.set_total, 1)
        self.assertEqual(len(findings.rewrite_question), 1)
        self.assertEqual(findings.rewrite_question[0].regex, "^/risky/(.*)$")
        self.assertEqual(findings.rewrite_question[0].replacement, "/internal?from=risky")

    def test_ignores_malformed_rewrite_without_counting_it(self):
        config = """
        rewrite ^/missing-replacement;
        rewrite ^/valid/(.*)$ /valid/$1 last;
        """

        findings = scan.scan_nginx_config(config)

        self.assertEqual(findings.rewrite_total, 1)
        self.assertEqual(findings.rewrite_question, [])


class VersionTests(unittest.TestCase):
    def test_classifies_affected_open_source_versions(self):
        self.assertTrue(scan.is_affected_nginx_version("nginx version: nginx/1.29.1"))
        self.assertTrue(scan.is_affected_nginx_version("nginx version: nginx/1.30.0"))

    def test_classifies_fixed_open_source_versions(self):
        self.assertFalse(scan.is_affected_nginx_version("nginx version: nginx/1.30.1"))
        self.assertFalse(scan.is_affected_nginx_version("nginx version: nginx/1.31.0"))

    def test_unknown_version_is_not_marked_affected(self):
        self.assertFalse(scan.is_affected_nginx_version("not nginx"))


class KubernetesCommandTests(unittest.TestCase):
    def test_load_running_containers_uses_all_namespaces_by_default(self):
        args = type("Args", (), {"timeout": 1, "kubectl": "kubectl", "kubeconfig": None, "context": None, "namespace": None})()
        calls = []

        def fake_run_command(command, timeout):
            calls.append(command)
            payload = {"items": []}
            return type("Result", (), {"returncode": 0, "stdout": __import__("json").dumps(payload), "stderr": ""})()

        with patched_attr(scan, "run_command", fake_run_command):
            containers = scan.load_running_containers(args)

        self.assertEqual(containers, [])
        self.assertEqual(calls[0], ["kubectl", "get", "pods", "-A", "-o", "json"])

    def test_load_running_containers_uses_requested_namespace_when_provided(self):
        args = type("Args", (), {"timeout": 1, "kubectl": "kubectl", "kubeconfig": None, "context": None, "namespace": "apps"})()
        calls = []

        def fake_run_command(command, timeout):
            calls.append(command)
            payload = {"items": []}
            return type("Result", (), {"returncode": 0, "stdout": __import__("json").dumps(payload), "stderr": ""})()

        with patched_attr(scan, "run_command", fake_run_command):
            containers = scan.load_running_containers(args)

        self.assertEqual(containers, [])
        self.assertEqual(calls[0], ["kubectl", "get", "pods", "-n", "apps", "-o", "json"])

    def test_discovery_command_uses_ps_fallback(self):
        command = scan.build_discover_nginx_command()

        self.assertIn("ps", command)
        self.assertIn("nginx: master", command)
        self.assertIn("/proc/$pid/exe", command)

    def test_config_reader_prefers_nginx_t_before_ingress_conf_fallback(self):
        args = type("Args", (), {"ingress_conf": True, "timeout": 1, "kubectl": "kubectl", "kubeconfig": None, "context": None})()
        target = scan.ContainerTarget("ingress-nginx", "pod-a", "controller", "registry.k8s.io/ingress-nginx/controller:v1")
        calls = []

        def fake_run_command(command, timeout):
            calls.append(command[-1])
            if "nginx -T" in command[-1]:
                return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "nginx: [emerg] test\n"})()
            return type("Result", (), {"returncode": 0, "stdout": "events {}", "stderr": ""})()

        with patched_attr(scan, "run_command", fake_run_command):
            config, source = scan.read_nginx_config(args, target, "nginx")

        self.assertEqual(source, "live /etc/nginx/nginx.conf")
        self.assertEqual(config, "events {}")
        self.assertIn("nginx -T", calls[0])

    def test_config_reader_does_not_use_ingress_fallback_when_nginx_t_succeeds(self):
        args = type("Args", (), {"ingress_conf": True, "timeout": 1, "kubectl": "kubectl", "kubeconfig": None, "context": None})()
        target = scan.ContainerTarget("ingress-nginx", "pod-a", "controller", "registry.k8s.io/ingress-nginx/controller:v1")
        calls = []

        def fake_run_command(command, timeout):
            calls.append(command[-1])
            return type("Result", (), {"returncode": 0, "stdout": "rewrite ^/x$ /y last;", "stderr": ""})()

        with patched_attr(scan, "run_command", fake_run_command):
            config, source = scan.read_nginx_config(args, target, "nginx")

        self.assertEqual(source, "nginx -T")
        self.assertEqual(config, "rewrite ^/x$ /y last;")
        self.assertEqual(len(calls), 1)

    def test_config_reader_does_not_use_ingress_fallback_for_regular_container(self):
        args = type("Args", (), {"ingress_conf": True, "timeout": 1, "kubectl": "kubectl", "kubeconfig": None, "context": None})()
        target = scan.ContainerTarget("default", "pod-a", "app", "example/app:latest")
        calls = []

        def fake_run_command(command, timeout):
            calls.append(command[-1])
            return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "nginx -T failed"})()

        with patched_attr(scan, "run_command", fake_run_command):
            config, source = scan.read_nginx_config(args, target, "nginx")

        self.assertEqual(source, "nginx -T")
        self.assertEqual(config, "nginx -T failed")
        self.assertEqual(len(calls), 1)


class ClusterSummaryTests(unittest.TestCase):
    def test_scan_cluster_summarizes_triggers_errors_and_affected_versions(self):
        args = type("Args", (), {"workers": 1})()
        targets = [
            scan.ContainerTarget("default", "safe", "nginx", "nginx:1.31"),
            scan.ContainerTarget("default", "risky", "nginx", "nginx:1.29"),
            scan.ContainerTarget("default", "broken", "nginx", "nginx:1.29"),
        ]

        def fake_scan_container(_args, target):
            if target.pod == "broken":
                raise RuntimeError("exec failed")
            if target.pod == "risky":
                return {
                    "namespace": target.namespace,
                    "pod": target.pod,
                    "container": target.container,
                    "affected_version": True,
                    "rewrite_total": 2,
                    "set_total": 1,
                    "rewrite_question_total": 1,
                    "rewrite_question": [{"line": 7, "directive": "rewrite ^/x$ /y?z=1;"}],
                }
            return {
                "namespace": target.namespace,
                "pod": target.pod,
                "container": target.container,
                "affected_version": False,
                "rewrite_total": 1,
                "set_total": 0,
                "rewrite_question_total": 0,
                "rewrite_question": [],
            }

        with patched_attr(scan, "load_running_containers", lambda _args: targets):
            with patched_attr(scan, "scan_container", fake_scan_container):
                report = scan.scan_cluster(args)

        self.assertEqual(report["containers_checked"], 3)
        self.assertEqual(report["nginx_containers"], 2)
        self.assertEqual(report["affected_version_containers"], 1)
        self.assertEqual(report["total_rewrites"], 3)
        self.assertEqual(report["total_sets"], 1)
        self.assertEqual(report["rift_rewrite_question_triggers"], 1)
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("default/broken/nginx", report["errors"][0])


if __name__ == "__main__":
    unittest.main()
