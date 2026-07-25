# Kubernetes NGINX Rift Audit

Read-only Kubernetes scanner for NGINX Rift, CVE-2026-42945. It looks for NGINX
containers in running pods, reads their effective NGINX configuration, and
reports `rewrite` directives whose replacement contains a literal `?`.

The scanner uses Python standard library plus the local `kubectl` binary. It
does not create, update, or delete Kubernetes resources.

## Quick Start

Run against the current kubeconfig context:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/kube-audit/nginx_rift_k8s_scan.py \
  | python3 -
```

Run with an explicit kubeconfig:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/kube-audit/nginx_rift_k8s_scan.py \
  | python3 - --kubeconfig /path/to/kubeconfig
```

Run with an explicit context and JSON output:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/kube-audit/nginx_rift_k8s_scan.py \
  | python3 - --context my-context --json
```

## What It Checks

For each running container, the script tries to find `nginx` or `openresty`.
For containers with NGINX, it collects:

- `nginx -v` version output
- effective config via `nginx -T`
- live `/etc/nginx/nginx.conf` fallback for `ingress-nginx` controllers when `nginx -T` fails

It then parses `rewrite` directives and flags replacements containing a literal
`?`, for example:

```nginx
rewrite ^/api/(.*)$ /internal?migrated=true;
```

This is the key NGINX Rift configuration primitive described in the public PoC.
The script also reports affected NGINX Open Source versions, but version alone
does not prove exploitability; the dangerous rewrite pattern must be present in
the active configuration.

## Exit Codes

- `0`: no rewrite replacement containing literal `?` was found
- `1`: at least one potential NGINX Rift rewrite trigger was found
- `2`: scan failed or completed with partial errors

## Options

```text
--kubeconfig PATH       kubeconfig path
--context NAME          kubeconfig context
--namespace NAME        scan one namespace instead of all namespaces
--timeout SECONDS       per-kubectl-call timeout, default 20
--workers N             parallel kubectl exec workers, default 8
--json                  emit JSON report
--verbose               include per-container details
--no-ingress-conf       disable /etc/nginx/nginx.conf fallback for ingress-nginx when nginx -T fails
```

## Required Permissions

The current Kubernetes identity needs permission to:

- list pods
- exec into pods

No write permissions are required.
