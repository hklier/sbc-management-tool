# SBC management tool

Oracle SBC HTTPS console, SIPREC recorder, offline transcription worker, and SNMP trap receiver. The original handoff is documented in [README.txt](README.txt) and [CONFIGURATION.txt](CONFIGURATION.txt). The recorder's GPL-3.0 license and attribution remain in `siprec/`.

## Lab deployment

- Console: **https://192.168.0.241**, username **admin**. The initial certificate is self-signed and valid for this IP address. The generated password and private trap community are kept outside this repository.
- Namespace and Argo CD application: `sbc-management-tool`.
- One pod, four containers, pinned to `k8s-worker2`. Deployment strategy: `Recreate`. This application is designed for one active instance; updates interrupt the web session and active recordings.
- SIPREC destination: `192.168.0.241:5060`, UDP or TCP. Media: UDP `20000-20199`. Codecs: PCMU and PCMA, unencrypted SIP/RTP.
- SNMP trap destination: `192.168.0.241:162/UDP`, SNMPv1/v2c with the separately supplied private community. SNMPv3 polling supports SHA256/SHA512 with AES128. SNMPv3 traps are not implemented.
- MetalLB preserves the source IP using `externalTrafficPolicy: Local`; SIP and all media ports select the same single recorder pod.

## Git and deployment

`deploy/kubernetes/base` contains Kustomize resources; `deploy/kubernetes/argocd-application.json` connects Argo CD to the `main` branch. Image references are pinned to published digests. Argo CD automatically reconciles changes to Git. `deploy/Dockerfile` defines the three image builds; images are stored in the existing private-LAN registry. The initial recorder image packages the validated GitHub Actions binary on the console runtime, with its source revision recorded in OCI image labels.

GitHub Actions runs the console tests, Oracle metadata/re-INVITE regression tests, and a Linux recorder build, with the recorder binary available as a downloadable artifact. A manual Actions run also builds all three images and provides downloadable image archives. GitHub-hosted runners have no access to the private cluster or LAN registry.

To release from a trusted Linux checkout with Podman and registry access:

```sh
git pull --ff-only
bash deploy/build-release.sh 0.1.1
git diff -- deploy/kubernetes/base/kustomization.yaml
git add deploy/kubernetes/base/kustomization.yaml
git commit -m 'Deploy SBC Console 0.1.1'
git push origin main
```

The registry currently uses HTTP on a private LAN; `REGISTRY_TLS_VERIFY=false` matches its existing configuration. Configure TLS and set `REGISTRY_TLS_VERIFY=true` when upgrading the registry. Revert the deployment image-reference commit to roll back software; a Git revert does not restore application data.

## Configure with one private YAML file

Use Python 3.12 or newer and install the helper dependencies:

```sh
python -m pip install -r deploy/requirements-config.txt
```

Copy `deploy/config.example.yaml` **outside the repository**, for example to `../deployment-private/config.private.yaml`. Restrict access to that directory. The completed YAML includes SBC credentials, HTTPS/SSH fingerprints, the trusted CA, SNMP settings, trap communities, console login, console TLS, the MetalLB endpoint, and SIPREC addresses/ports. Inline PEM certificates/keys and paths relative to the YAML are supported. The existing deployment's populated private YAML is stored outside this checkout.

Validate, render, and apply private settings:

```sh
python deploy/configure.py --config ../deployment-private/config.private.yaml --check
python deploy/configure.py --config ../deployment-private/config.private.yaml --apply-private
git diff -- deploy/kubernetes/base/resources.json
git add deploy/kubernetes/base/resources.json
git commit -m 'Update SBC Console configuration'
git push origin main
```

`--check` validates without writing or contacting Kubernetes. `--apply-private` creates/updates the three named Kubernetes Secrets, then the Git commit allows Argo CD to roll out the new settings. The namespace must already exist for private bootstrap. Use local `kubectl` or configure `management.transport: ssh` to use the control node; PuTTY `.ppk` keys use `plink` in batch mode, with cached host trust or an explicit `host_key`. SSH keys and Git authentication are read from your local environment/files and are never copied into the public render.

The helper renders `deploy/kubernetes/base/resources.json` from `deploy/kubernetes/template/resources.json`. **Edit the private YAML, not the generated base file.** Image versions stay managed separately in `kustomization.yaml`. Deployment placement, persistent volumes, and resource limits remain infrastructure settings in the template; the helper does not move data or change SBC configuration.

Private outputs are stored next to the YAML in `<filename-without-extension>.generated/`. They include the Secret manifest, rendering state, public console certificate, and console password when available. Back up both the YAML and that directory when using `generate` for passwords, trap communities, or certificates. The input and generated private files are refused inside the checkout. Do not commit them to any repository. The renderer emits only non-secret settings and an opaque Secret revision into Git.

Changing credentials or TLS generates a new opaque revision; changing public settings updates a public configuration hash. Argo CD restarts the single-instance workload after the rendered change is pushed. Re-rendering unchanged YAML reuses hashes, generated passwords/communities, and certificates and does not cause another rollout. Configuration changes interrupt sessions and active recordings; apply them between calls. The YAML configures only the application: SNMP allowlists, CDR generation, SIPREC routing, and trap-version compatibility still need SBC-side setup.

Use `console.password` for a quoted password or `generate`; alternatively use `console.password_hash` in the application's PBKDF2 format. Use `console.tls.mode: supplied` for inline/file-based certificate material, or `self-signed` to generate a certificate with the endpoint IP in its SAN. SNMPv3 accepts SHA256/SHA512 with AES128; traps remain v1/v2c.

## Manual private bootstrap reference

Before applying the Argo CD Application, create the namespace and the following Secrets through a trusted administrative channel:

| Secret | Required keys |
| --- | --- |
| `sbc-console-credentials` | `SBC_HOST`, `SBC_USER`, `SBC_PASSWORD`, `SBC_FINGERPRINT`, `SBC_SSH_FINGERPRINT`, `APP_PASSWORD_HASH`, `SNMP_USER`, `SNMP_AUTH_KEY`, `SNMP_PRIV_KEY`, `SNMP_TRAP_COMMUNITIES` |
| `sbc-console-tls` | `tls.crt`, `tls.key` |
| `sbc-console-trust` | `sbc-ca.crt` |

Use `generate-console-password.py` to rotate the console password hash. Obtain the remote HTTPS and SSH fingerprints through a trusted channel. `SNMP_TRAP_COMMUNITIES` is a JSON array string. Credentials, keys, recordings, and runtime state must never be committed. Secrets are deliberately outside Argo CD's Git resources; a new-cluster recovery requires private bootstrap material.

```sh
kubectl apply -f deploy/kubernetes/argocd-application.json
```

## Data and operations

The static persistent volume uses `/var/lib/sbc-management-tool` on `k8s-worker2`, with node affinity and reclaim policy `Retain`. It is protected against Argo CD pruning/deletion. The declared 50 GiB is a scheduling value, **not a host filesystem quota**. SQLite WAL stays on local storage. Recordings and transcripts share that volume, and all components use UID/GID 10001.

There is no automatic node failover. To move the application, stop it, back up/copy the entire directory with ownership preserved, and update both workload placement and PV node affinity. Take consistent backups with the pod stopped, including SQLite WAL/SHM files, recordings, and transcripts. Protect Secrets separately. Monitor the worker's real free disk space and agree a recording-retention policy before sustained use; the inherited recorder retention is effectively disabled (36500 days).

Containers run without root privileges, with read-only root filesystems, dropped capabilities, no Kubernetes API token, and local health probes. The initial permissions container runs as root to prepare only the mounted data directories. The console's authenticated REST activity viewer can display SBC authentication tokens; restrict console access accordingly.

The transcription model is downloaded at image-build time from `Systran/faster-whisper-tiny`, revision `d90ca5fe260221311c53c58e660288d3deb8d356`. Inference runs locally and processes one job at a time. Container readiness checks only local component health and does not modify or poll the SBC.

## Acceptance and SBC setup

The deployment does not change SBC configuration. The SBC owner must configure the SIPREC destination and trap destination/community, and allow management/SNMP traffic from the cluster. Validate console login, read-only configuration, CDR/trace/LRT access, SNMP polling, a test trap, and a real recorded call with both directions and transcription. Do not save or activate SBC configuration merely to test connectivity.

`python deploy/check-siprec.py 192.168.0.241` sends labelled synthetic media through the external UDP/TCP SIP and RTP endpoint. It creates a self-test recording; verify both stored audio legs and the combined stereo WAV in the console afterward. This test does not modify the SBC.

The original `SOURCE-MANIFEST.json` describes the received handoff, before Kubernetes adaptations. Git history records subsequent changes.
