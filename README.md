# SBC management tool

Oracle SBC HTTPS console, SIPREC recorder, offline transcription worker, and SNMP trap receiver. The original handoff is documented in [README.txt](README.txt) and [CONFIGURATION.txt](CONFIGURATION.txt). The recorder's GPL-3.0 license and attribution remain in `siprec/`.

See the [Kubernetes deployment and user guide](docs/KUBERNETES-USER-GUIDE.md) for prerequisites, installation into another cluster, Argo CD, certificates, HDR sources, and recovery. The new `deploy/kubernetes/quickstart` profile needs no application bootstrap inputs: it generates HTTPS and creates **admin / oracle**, with an API-enforced password change at first sign-in. Cluster storage and image-pull prerequisites still apply. Existing installations retain their current accounts and certificates.

**WebGUI certificate** provides custom subject/SAN CSR generation, CSR download, and signed PEM-chain validation/import. Private CSR keys remain on the persistent volume; activation changes new HTTPS connections without a pod restart. **HDR Reporting** configures a mounted directory or an SFTP CSV source with password/private-key authentication, encrypted credentials, server host-key verification, and a bounded read-only CSV inventory. HDR analysis is planned for a later release.

## Lab deployment

- Console: **https://192.168.0.241**, username **admin**. The initial certificate is self-signed and valid for this IP address. The generated password and private trap community are kept outside this repository.
- Namespace and Argo CD application: `sbc-management-tool`.
- One pod, four containers, pinned to `k8s-worker2`. Deployment strategy: `Recreate`. This application is designed for one active instance; updates interrupt the web session and active recordings.
- SIPREC destination: `192.168.0.241:5060`, UDP or TCP. Media: UDP `20000-20199`. Codecs: PCMU and PCMA, unencrypted SIP/RTP.
- SNMP trap destination: `192.168.0.241:162/UDP`, SNMPv1/v2c with the separately supplied private community. SNMPv3 polling supports SHA256/SHA512 with AES128. SNMPv3 traps are not implemented.
- MetalLB preserves the source IP using `externalTrafficPolicy: Local`; SIP and all media ports select the same single recorder pod.

## Console users and passwords

Your signed-in username appears at the top right. Open its dropdown for **Update password**, **Manage users**, **Manage devices**, or **Sign out**. Management entries appear for administrators. **Users & passwords** is also available in the sidebar. Every signed-in user can change their own password after confirming the current one. Administrators can list accounts, add console users or additional administrators, and reset a password after confirming their own administrator password. New passwords require 12–1024 characters; usernames are case-insensitive. Console users can operate managed SBCs; administrators also manage accounts and device profiles.

Accounts and salted PBKDF2 password hashes are stored in `STATE_DIR/users.sqlite3` on the persistent volume. Passwords cannot be viewed. Password changes revoke previous sessions and rotate the current session cookie. UI account changes are recorded in the operation audit without passwords.

The YAML `console.username` and `console.password`/`password_hash` initialize the first administrator **only when the account database is empty**. Later YAML changes, image upgrades, and restarts do not overwrite accounts or UI password changes. Back up the user database with the other application state. Your existing administrator credentials are preserved on first upgrade.

If all administrators lose access, a cluster administrator can explicitly restore the administrator from the bootstrap values loaded by the running console container:

```sh
kubectl exec -n sbc-management-tool deploy/sbc-console -c console -- python users_tools.py --reset-bootstrap
```

Other accounts remain intact; the recovered account's old sessions are invalidated. If you changed bootstrap credentials through YAML, complete that rollout before running recovery. Do not delete the account database to recover a password.

## Managed devices

Open **Devices** to add, edit, or delete a connection profile. The form includes a name, management IPv4 address, REST API username (default `admin`) and password, SSH port and public host key, a PEM CA certificate or bundle, and conditional SNMP settings. Polling supports disabled, v1, v2c, and v3; v3 supports noAuthNoPriv, authNoPriv, or authPriv, MD5/SHA1/SHA224/SHA256/SHA384/SHA512 authentication, and AES128 privacy. Trap reception remains v1/v2c; optional trap communities belong to each device. Receiver changes take effect within five seconds.

To import the SBC's RSA public host key, run `show security public-host-key rsa` on the SBC and paste the public-key output or upload a public-key file. **Read key from SBC** reads an unverified RSA key without signing in; compare it with the trusted command output before saving. OpenSSH, wrapped SBC output, SSH2, and PEM public keys are accepted. Never import private keys. HTTPS connections validate the uploaded CA chain and the management IP against the server certificate. Blank password fields on edits preserve stored credentials; passwords and communities are never returned by the editing API.

Choose the active device in the sidebar. Selection belongs to the login session; switching reloads the workspace. Configuration snapshots, route-table plans, CDR caches, SNMP clients, and REST/SFTP credentials are isolated by device. A stale tab cannot write to a newly selected or updated device. Complete pending SBC operations before editing or deleting its profile. Deleting a profile retains the SBC configuration, historical audit/trap data, and shared SIPREC recordings. The recording service and archive remain shared across devices.

On the first upgrade, the existing YAML/environment SBC and SNMP settings initialize a `bootstrap` device, preserving the existing SSH fingerprint and HTTPS trust. Subsequent YAML changes do not overwrite managed-device edits or recreate deleted profiles. Continue using YAML for console, cluster, recording, and initial connection settings; use **Devices** for ongoing SBC connection changes. Existing fingerprint-only HTTPS trust is retained until a CA is supplied when editing.

Device records are encrypted in `STATE_DIR/devices.sqlite3`; the encryption key is `STATE_DIR/device-encryption.key`, readable only by the application account. Back up the database and matching key together with application state, outside Git. A missing or mismatched key fails closed. This protects database-only copies; anyone with access to both files can decrypt credentials. Keep the deployment at one active replica on its retained persistent volume.

## Editing local route entries

Open **Local route tables**, select a loaded table, and choose **Edit** on the entry. The form loads its number/string or DID range, description, next-hop expressions, types, and optional attributes. **Review changes** shows the original and proposed entry. **Save file** uses the same verified backups, file hash checks, and atomic replacement as adding or deleting entries. Other entries, including duplicate matches, stay in their original order. Saving changes the source file; **Reload in SBC** applies it to live routing. Reloading remains an explicit choice. Previewing and cancelling make no SBC changes.

The editor accepts up to ten next hops. Entries with structured next-hop XML are rejected rather than silently dropping unsupported content. Existing table/route/user metadata is retained, and both plain XML and gzip files are supported.

## Git and deployment

`deploy/kubernetes/base` contains Kustomize resources; `deploy/kubernetes/argocd-application.json` connects Argo CD to the `main` branch. Image references are pinned to published digests. Argo CD automatically reconciles changes to Git. `deploy/Dockerfile` defines the three image builds; images are stored in the existing private-LAN registry. The initial recorder image packages the validated GitHub Actions binary on the console runtime, with its source revision recorded in OCI image labels.

GitHub Actions runs the console tests, Oracle metadata/re-INVITE regression tests, and a Linux recorder build, with the recorder binary and deployable console image available as downloadable artifacts. A manual Actions run also builds all three images and provides downloadable image archives. GitHub-hosted runners have no access to the private cluster or LAN registry.

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
