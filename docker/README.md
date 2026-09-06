# AntiNAT Agent container

Build the pinned, non-root Agent image from this repository:

```bash
docker build --tag antinat-agent:local .
```

The image stores durable Agent state in `/var/lib/antinat` and logs in
`/var/log/antinat`. `docker/stage-enrollment.sh` consumes an enrollment token
from a protected file or Docker secret before starting the Agent.

The container uses host networking because forwarding and same-source NAT
observation depend on the host network namespace. A production deployment
must provide `ANTINAT_ENDPOINT`, `ANTINAT_NODE`, and `ANTINAT_PIN`, plus a
one-time token file when enrolling a new node.
