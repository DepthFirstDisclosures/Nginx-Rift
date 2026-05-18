#!/usr/bin/env python3
"""Read-only Kubernetes scanner for NGINX Rift (CVE-2026-42945).

The scanner uses only Python stdlib and the local kubectl binary. It does not
create, update, or delete Kubernetes resources; it only runs get and exec calls.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import re
import shlex
import subprocess
import sys
from typing import Any


AFFECTED_MIN = (0, 6, 27)
AFFECTED_MAX = (1, 30, 0)


@dataclasses.dataclass(frozen=True)
class RewriteFinding:
    line: int
    regex: str
    replacement: str
    directive: str


@dataclasses.dataclass(frozen=True)
class ConfigFindings:
    lines: int
    rewrite_total: int
    set_total: int
    rewrite_question: list[RewriteFinding]


@dataclasses.dataclass(frozen=True)
class ContainerTarget:
    namespace: str
    pod: str
    container: str
    image: str


def parse_version_tuple(version_text: str) -> tuple[int, int, int] | None:
    match = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", version_text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def is_affected_nginx_version(version_text: str) -> bool:
    version = parse_version_tuple(version_text)
    if version is None:
        return False
    return AFFECTED_MIN <= version <= AFFECTED_MAX


def scan_nginx_config(config_text: str) -> ConfigFindings:
    rewrite_total = 0
    set_total = 0
    rewrite_question: list[RewriteFinding] = []

    lines = config_text.splitlines()
    for line_number, raw_line in enumerate(lines, 1):
        directive = raw_line.strip().rstrip(";")
        if not directive or directive.startswith("#"):
            continue

        if re.match(r"^set\s+", directive):
            set_total += 1

        if not re.match(r"^rewrite\s+", directive):
            continue

        try:
            tokens = shlex.split(directive, comments=True, posix=True)
        except ValueError:
            continue

        if len(tokens) < 3:
            continue

        rewrite_total += 1
        regex = tokens[1]
        replacement = tokens[2]
        if "?" in replacement:
            rewrite_question.append(
                RewriteFinding(
                    line=line_number,
                    regex=regex,
                    replacement=replacement,
                    directive=directive,
                )
            )

    return ConfigFindings(
        lines=len(lines),
        rewrite_total=rewrite_total,
        set_total=set_total,
        rewrite_question=rewrite_question,
    )


def run_command(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def kubectl_base(args: argparse.Namespace) -> list[str]:
    command = [args.kubectl]
    if args.kubeconfig:
        command.extend(["--kubeconfig", args.kubeconfig])
    if args.context:
        command.extend(["--context", args.context])
    return command


def kubectl_exec_base(args: argparse.Namespace, target: ContainerTarget) -> list[str]:
    return kubectl_base(args) + [
        "-n",
        target.namespace,
        "exec",
        target.pod,
        "-c",
        target.container,
        "--",
        "sh",
        "-c",
    ]


def load_running_containers(args: argparse.Namespace) -> list[ContainerTarget]:
    command = kubectl_base(args) + ["get", "pods"]
    if args.namespace:
        command.extend(["-n", args.namespace])
    else:
        command.append("-A")
    command.extend(["-o", "json"])

    result = run_command(command, args.timeout)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "kubectl get pods failed")

    data = json.loads(result.stdout)
    targets: list[ContainerTarget] = []
    for item in data.get("items", []):
        if item.get("status", {}).get("phase") != "Running":
            continue
        namespace = item.get("metadata", {}).get("namespace", args.namespace or "default")
        pod = item.get("metadata", {}).get("name", "")
        for container in item.get("spec", {}).get("containers", []):
            targets.append(
                ContainerTarget(
                    namespace=namespace,
                    pod=pod,
                    container=container.get("name", ""),
                    image=container.get("image", ""),
                )
            )
    return targets


def build_discover_nginx_command() -> str:
    return (
        "command -v nginx 2>/dev/null "
        "|| command -v openresty 2>/dev/null "
        "|| { test -x /usr/local/openresty/nginx/sbin/nginx "
        "&& printf %s /usr/local/openresty/nginx/sbin/nginx; } "
        "|| { pid=$(ps -eo pid,args 2>/dev/null "
        "| awk '/nginx: master/ && !/awk/ {print $1; exit}'); "
        "test -n \"$pid\" && readlink -f /proc/$pid/exe 2>/dev/null; } "
        "|| true"
    )


def discover_nginx_binary(args: argparse.Namespace, target: ContainerTarget) -> str | None:
    script = build_discover_nginx_command()
    result = run_command(kubectl_exec_base(args, target) + [script], args.timeout)
    if result.returncode != 0:
        return None
    binary = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
    return binary or None


def read_nginx_version(args: argparse.Namespace, target: ContainerTarget, binary: str) -> str:
    result = run_command(
        kubectl_exec_base(args, target) + [f"{shlex.quote(binary)} -v 2>&1"],
        args.timeout,
    )
    text = (result.stdout + result.stderr).strip()
    return text.splitlines()[0] if text else "unknown"


def read_nginx_config(args: argparse.Namespace, target: ContainerTarget, binary: str) -> tuple[str, str]:
    result = run_command(
        kubectl_exec_base(args, target) + [f"{shlex.quote(binary)} -T 2>&1"],
        args.timeout,
    )
    config_text = result.stdout + result.stderr
    if result.returncode == 0 and config_text.strip():
        return config_text, "nginx -T"

    if args.ingress_conf and (
        target.namespace == "ingress-nginx" or "ingress-nginx/controller" in target.image
    ):
        result = run_command(
            kubectl_exec_base(args, target)
            + ["sed -n '1,999999p' /etc/nginx/nginx.conf 2>/dev/null"],
            args.timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout, "live /etc/nginx/nginx.conf"

    return config_text, "nginx -T"


def scan_container(args: argparse.Namespace, target: ContainerTarget) -> dict[str, Any] | None:
    binary = discover_nginx_binary(args, target)
    if not binary:
        return None

    version = read_nginx_version(args, target, binary)
    config_text, config_source = read_nginx_config(args, target, binary)
    findings = scan_nginx_config(config_text)
    return {
        "namespace": target.namespace,
        "pod": target.pod,
        "container": target.container,
        "image": target.image,
        "binary": binary,
        "version": version,
        "affected_version": is_affected_nginx_version(version),
        "config_source": config_source,
        "lines": findings.lines,
        "rewrite_total": findings.rewrite_total,
        "set_total": findings.set_total,
        "rewrite_question_total": len(findings.rewrite_question),
        "rewrite_question": [dataclasses.asdict(item) for item in findings.rewrite_question],
    }


def scan_cluster(args: argparse.Namespace) -> dict[str, Any]:
    targets = load_running_containers(args)
    scanned: list[dict[str, Any]] = []
    errors: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {executor.submit(scan_container, args, target): target for target in targets}
        for future in concurrent.futures.as_completed(future_map):
            target = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - CLI should report and continue.
                errors.append(f"{target.namespace}/{target.pod}/{target.container}: {exc}")
                continue
            if result:
                scanned.append(result)

    scanned.sort(key=lambda item: (item["namespace"], item["pod"], item["container"]))
    trigger_total = sum(item["rewrite_question_total"] for item in scanned)
    return {
        "containers_checked": len(targets),
        "nginx_containers": len(scanned),
        "affected_version_containers": sum(1 for item in scanned if item["affected_version"]),
        "total_rewrites": sum(item["rewrite_total"] for item in scanned),
        "total_sets": sum(item["set_total"] for item in scanned),
        "rift_rewrite_question_triggers": trigger_total,
        "containers": scanned,
        "errors": errors,
    }


def print_human_report(report: dict[str, Any], verbose: bool) -> None:
    print("NGINX Rift Kubernetes Audit")
    print()
    print(f"Containers checked: {report['containers_checked']}")
    print(f"NGINX containers found: {report['nginx_containers']}")
    print(f"Affected-version containers: {report['affected_version_containers']}")
    print(f"Total rewrite directives: {report['total_rewrites']}")
    print(f"Total set directives: {report['total_sets']}")
    print(f"Rift rewrite '?' triggers: {report['rift_rewrite_question_triggers']}")
    if report["errors"]:
        print(f"Scan errors: {len(report['errors'])}")
    print()

    if report["rift_rewrite_question_triggers"]:
        print("Potential NGINX Rift triggers:")
        for item in report["containers"]:
            for finding in item["rewrite_question"]:
                print(
                    f"- {item['namespace']}/{item['pod']}/{item['container']} "
                    f"line {finding['line']}: {finding['directive']}"
                )
        print()
        print("Verdict: potential CVE-2026-42945 trigger found.")
    else:
        print("Verdict: no rewrite replacement containing literal '?' was found.")

    if verbose:
        print()
        print("Scanned NGINX containers:")
        for item in report["containers"]:
            affected = "affected-version" if item["affected_version"] else "fixed-or-unknown-version"
            print(
                f"- {item['namespace']}/{item['pod']}/{item['container']} "
                f"{item['version']} {affected} rewrites={item['rewrite_total']} "
                f"sets={item['set_total']} source={item['config_source']}"
            )

    if report["errors"] and verbose:
        print()
        print("Errors:")
        for error in report["errors"]:
            print(f"- {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Kubernetes audit for NGINX Rift (CVE-2026-42945)."
    )
    parser.add_argument("--kubectl", default="kubectl", help="kubectl binary path")
    parser.add_argument("--kubeconfig", help="kubeconfig path")
    parser.add_argument("--context", help="kubeconfig context")
    parser.add_argument("--namespace", help="scan one namespace instead of all namespaces")
    parser.add_argument("--timeout", type=int, default=20, help="per-kubectl-call timeout in seconds")
    parser.add_argument("--workers", type=int, default=8, help="parallel kubectl exec workers")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--verbose", action="store_true", help="include per-container details")
    parser.add_argument(
        "--no-ingress-conf",
        dest="ingress_conf",
        action="store_false",
        help="disable /etc/nginx/nginx.conf fallback for ingress-nginx when nginx -T fails",
    )
    parser.set_defaults(ingress_conf=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = scan_cluster(args)
    except Exception as exc:  # noqa: BLE001 - CLI top-level reporting.
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human_report(report, args.verbose)

    if report["rift_rewrite_question_triggers"]:
        return 1
    if report["errors"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
