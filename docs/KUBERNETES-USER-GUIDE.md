# SBC Console: deployment and user guide

## 1. Choose a deployment profile

The **quick-start profile** installs the WebGUI, device management, LRT management, user management, WebGUI certificate management, HDR source configuration, and SNMP trap receiver. It creates an empty persistent state area. No SBC credentials, application password Secret, private YAML, or TLS certificate are needed before starting it. The app generates its initial self-signed certificate and creates **admin / oracle**. The first sign-in is restricted to changing that password.

The **existing lab profile**, `deploy/kubernetes/base`, also runs the SIPREC recorder and offline transcription worker. It uses the lab's node-bound storage, network address, and externally supplied bootstrap Secrets. Keep this profile for the existing installation. Do not apply the quick-start profile over an existing installation's PVC or namespace. Upgrading preserves existing users, passwords, managed devices, recordings, and certificates; it does not recreate the default account.

Application bootstrap needs no interactive answers. Cluster prerequisites—including a working image registry and storage provisioning—must already be available. Exposure of SIP/RTP, trap traffic, or an external HTTPS address is a cluster/network configuration task.

For a new installation in the current lab, `deploy/kubernetes/quickstart-nfs` selects the existing `nfs-csi` StorageClass automatically. It uses the same zero-input application bootstrap. The generic `quickstart` profile uses the target cluster's default StorageClass.

## 2. Requirements and prerequisites

| Area | Requirement |
|---|---|
| Cluster | A working Kubernetes cluster with DNS, CNI networking, and schedulable Linux AMD64 workers. This release is validated on Kubernetes 1.36. |
| Access | `kubectl` configured for the target cluster; permissions to manage a namespace, PVC, Deployment, and Service. The app itself does not need Kubernetes API access. |
| Storage | A default StorageClass that dynamically provisions a durable writable ReadWriteOnce PVC, or an administrator-provisioned PVC. It must provide reliable POSIX locking and flush semantics. The quick start requests 10 GiB. Keep one active replica. Use shared storage or correctly node-bound local storage; a hostPath PV without node affinity can appear empty when a pod moves to another node. |
| Filesystem permissions | A short initializer creates `/data/application` with group 10001 and mode 0770. Main containers run as UID/GID 10001 and create their private state beneath `/data/application/state`. The volume must allow this group preparation, including when NFS root-squash is enabled. |
| Pod policy | The supplied initializer runs as UID 0, with a read-only container filesystem and limited filesystem capabilities. Main containers run without root or capabilities. If your policy prohibits root initializers, have the storage administrator prepare the parent directory for group 10001 and remove the initializer before installing. |
| Images | Worker nodes must pull the referenced Linux AMD64 images. The supplied image reference uses the existing registry, `192.168.2.240:5000`; this is a private lab address, not a public image service. Outside this network, build or mirror the images to a registry reachable by your cluster and update the Kustomize image reference first. |
| Registry durability | Registry blobs and manifests need persistent, node-safe storage too. The lab registry uses retained shared NFS storage; see [Registry storage and recovery](REGISTRY-STORAGE.md). A registry backed by unbound node-local hostPath storage can lose access to its images after rescheduling. |
| Registry transport | Use HTTPS for a production registry. The existing lab registry uses HTTP and requires an administrator's containerd registry configuration on every eligible node. Do not disable registry verification cluster-wide. |
| Capacity | For the console and traps, start with 2 vCPU and 2 GiB free worker capacity and monitor usage. Recording/transcription require additional CPU, memory, and disk. The quick-start requests total 125m CPU and 192 MiB RAM, with higher limits. |
| Browser | A current browser with JavaScript and access to the forwarded or externally exposed HTTPS endpoint. |
| Administration | Keep the initial endpoint private until the initial password has been changed. The built-in initial password is intentionally public. |

Network access needed for the features you enable:

| Direction | Destination | Purpose |
|---|---|---|
| Browser to app | TCP 443, or local forwarded TCP 8443 | WebGUI HTTPS; internal app listener is 8443 |
| App to SBC | TCP 443 | SBC REST API |
| App to SBC | TCP 22 or configured SSH port | SFTP for LRTs, CDRs, and packet captures |
| App to SBC | UDP 161 or configured SNMP port | SNMP polling |
| SBC to exposed trap service | UDP 162 | SNMPv1/v2c traps; container listens on 1162 |
| App to HDR SFTP server | TCP 22 or configured port | Read-only HDR CSV directory listing |
| Workers to registry | Registry's TCP port | Image pulls |

If recording is enabled, additionally allow SBC-to-recorder SIP UDP/TCP 5060 and the configured RTP UDP range. The existing lab uses 20000–20199. These ports must reach the same recorder instance. The SBC must be able to reach the advertised media address; a browser port-forward does not expose SIP or RTP.

## 3. Prepare images for another cluster

Skip this section when your cluster already reaches the supplied registry. For a different registry, build the console image and push it using your organization's registry credentials:

```sh
git clone https://github.com/hklier/sbc-management-tool.git
cd sbc-management-tool
docker build --platform linux/amd64 --target console -f deploy/Dockerfile -t registry.example.com/sbc-console:0.4.3 .
docker push registry.example.com/sbc-console:0.4.3
cd deploy/kubernetes/quickstart
kustomize edit set image sbc-console=registry.example.com/sbc-console:0.4.3
cd ../../..
```

`kustomize edit` uses the standalone Kustomize executable; `kubectl apply -k` has a built-in renderer. You can instead edit the `images` entry in `deploy/kubernetes/quickstart/kustomization.yaml`. Prefer a registry digest after publishing. If your registry requires authentication, have the cluster administrator configure an imagePullSecret in the deployment namespace and reference it in the pod spec. Keep registry credentials out of Git.

For the optional full recording deployment, also build the `recorder` and `transcription` targets in `deploy/Dockerfile`, publish them, and update the corresponding image references. The transcription image bundles its model during the build; runtime processing is local and offline. Building it requires internet access and more time than the console build.

## 4. Install without application bootstrap inputs

Confirm cluster and storage availability:

```sh
kubectl get nodes
kubectl get storageclass
```

Apply the quick-start profile:

```sh
kubectl apply -k deploy/kubernetes/quickstart
kubectl -n sbc-console get pvc
kubectl -n sbc-console rollout status deployment/sbc-console --timeout=180s
kubectl -n sbc-console get pods
```

The PVC must become `Bound`; the pod should show **2/2 Running** for the console and traps. No application Secrets need to be created. If there is no default StorageClass, arrange storage before installation; do not work around an unbound PVC by using temporary storage for a production installation.

In the current lab, use `kubectl apply -k deploy/kubernetes/quickstart-nfs` instead of the generic apply command. Its default `hostpath` StorageClass has no PV node affinity; the NFS profile avoids creating application state that could appear empty after a node move. The NFS StorageClass must exist first. For another cluster, choose a durable default StorageClass or adapt this small storage overlay.

The profile deliberately avoids recursive pod `fsGroup` changes. With root-squashed NFS, kubelet cannot traverse the app's private UID-owned state directories during a later remount. The initializer prepares only a group-accessible parent; the application creates and owns the private state below it. Do not add recursive volume-ownership changes without testing rescheduling and permissions.

The quick-start profiles set `SQLITE_JOURNAL_MODE=DELETE` for rollback journaling, including on shared NFS storage. [SQLite does not support WAL journaling on a network filesystem](https://sqlite.org/wal.html). The existing node-local lab profile retains WAL mode. Only `WAL` and `DELETE` are accepted; do not select WAL for a network-backed state volume. Keep one active replica and use a storage service with reliable locking and flush semantics.

Open the initial endpoint privately:

```sh
kubectl -n sbc-console port-forward service/sbc-console 8443:443
```

Visit **https://127.0.0.1:8443**. The first certificate is self-signed, so your browser will require an explicit trust exception. A cluster administrator can inspect its public certificate fingerprint from the persistent state before accepting it:

```sh
kubectl -n sbc-console exec deploy/sbc-console -c console -- python -c "import os,json;from pathlib import Path;from certificate_tools import details;p=Path(os.environ['STATE_DIR'])/'web-tls';a=json.loads((p/'active.json').read_text());print(details((p/(a['id']+'.crt')).read_bytes())['sha256'])"
```

Sign in with **admin** and **oracle**. Enter the current password and choose a new password of at least 12 characters. The app blocks other application APIs until this change succeeds. The password is stored as a salted PBKDF2 hash; subsequent restarts and upgrades preserve it. Sign-out and password changes invalidate the relevant sessions.

There are initially no managed devices. Add them after signing in. No SBC connection is needed to complete the password change, manage the WebGUI certificate, or configure HDR access.

## 5. Add an SBC

Open **Devices → Add device** and provide:

1. A name and management IPv4 address.
2. REST API username, default `admin`, and its SBC password.
3. SNMP version and the fields shown for that version. Use Disabled if polling is not ready. SNMPv3 offers noAuthNoPriv, authNoPriv, and authPriv; the privacy algorithm is AES128.
4. SSH port and public host key. On the SBC, run `show security public-host-key rsa`. Paste the output or import a public-key file. **Read key from SBC** obtains an unverified candidate: compare it with the trusted command output before saving.
5. The public PEM CA certificate or CA bundle that verifies the SBC HTTPS server certificate. The server certificate must cover the management IP.

The REST credentials are also used for SBC SFTP access. The SBC account needs the relevant REST and file permissions. Ensure CDR generation, LRT files, and trace directories exist on the SBC; installing the app does not create them.

Optional private trap communities belong to the device. The receiver supports SNMPv1/v2c notifications, including when polling uses v3. Configure the SBC's trap destination and community separately. If a LoadBalancer is used, preserve the SBC source address: trap matching uses each device's management IP. NAT addresses must be accounted for in your network design.

Select the active device in the sidebar. Selection is per login session. Connection settings, file caches, and change plans are isolated by device. Administrators manage device profiles; console users can operate configured devices. Blank password fields preserve stored passwords when editing a profile.

For LRT changes, select a loaded table and choose **Edit**, **Review changes**, then **Save file**. Saving creates verified backups and uses file-hash checks and atomic replacement. **Reload in SBC** applies the saved file to live routing; previewing and cancelling do not change the SBC.

## 6. Replace the WebGUI certificate

The **WebGUI certificate** screen manages the app's own HTTPS listener. It is separate from the CA used to verify an SBC.

1. Establish the DNS name or IP through which users will access the console. Arrange its DNS and Service/LoadBalancer routing.
2. Open **WebGUI certificate** from the sidebar or the username dropdown.
3. Enter the CSR subject: common name and, optionally, organization, organizational unit, country, state, and locality.
4. Enter every required DNS name and IP SAN on separate lines. Include the management IP or forwarded address if it must continue to work. Choose an RSA key size.
5. Click **Generate CSR**, then **Download CSR** for the matching request. Submit the CSR to your certificate authority. The private key stays in the app's persistent state and is not downloadable through the UI or API.
6. Obtain the signed PEM server certificate and any intermediate certificates. Install the issuing CA in your browser trust store before activation. Put the server certificate first, followed by its issuing intermediates. The CA must retain all requested SAN names.
7. Select the matching pending request, import the PEM file, and choose **Validate and activate certificate**.
8. Reconnect using a covered DNS name or IP. Ensure the browser trusts the issuing CA.

The app verifies the key match, validity dates, requested SANs, server-auth usage where supplied, and chain ordering/signatures where a chain is provided. A rejected import leaves the current certificate active. Successful activation changes new TLS connections without restarting the pod; existing connections can finish. The imported certificate survives pod recreation and image upgrades. Unused pending requests can be removed; this deletes their private keys.

Use a direct HTTPS Service, a layer-4 load balancer, or TLS passthrough when the app certificate should be the certificate seen by the browser. If an Ingress terminates TLS, its public certificate is managed by that Ingress/controller instead; use that controller's certificate workflow. Do not expect changing the app listener certificate to change a separately terminating Ingress certificate.

## 7. Configure HDR Reporting

This release provides **one shared HDR source**, a connection check, and a CSV file inventory. It does not yet parse, import, aggregate, or analyse HDR CSV contents.

### Mounted directory

Use this when another service places files on storage mounted into the console:

1. Open **HDR Reporting** and select **Mounted directory**.
2. Enter an absolute directory beneath the displayed HDR root. The default is the persistent state's `hdr-inbox` directory.
3. Click **Save HDR source**, then **Test connection & list CSV files**.

For a separate incoming-data volume, have the administrator mount it at, for example, `/hdr`, and set `HDR_LOCAL_ROOT=/hdr` on the console container. A read-only mount is sufficient for listing. Ensure UID/GID 10001 can traverse the directory and read metadata. GUI paths are confined to this root. Local file symlinks and directories named `.csv` are excluded.

### Remote SFTP directory

Use an existing SFTP receiver as the destination for SBC HDR pushes; configure this app to read that receiver:

1. Select **Remote SFTP server** and enter its hostname/IPv4 address, port, and username.
2. Enter the CSV directory as an absolute path as seen by this SFTP account. A chrooted account may see `/incoming/hdr` even if the receiver uses a different filesystem path.
3. Supply the SFTP server's public host key through a trusted channel. This identifies the server.
4. Supply an account password, a client-authentication private key, or both. OpenSSH/PEM RSA, ECDSA, and Ed25519 keys are supported; convert PuTTY `.ppk` keys first. Enter the key passphrase when needed. This is distinct from the server's public host key.
5. Save the source, then test the saved connection and list files.

Credentials and private keys are encrypted on the persistent state volume. The API returns stored/not-stored indicators instead of their contents. Blank credentials keep saved values for the same server/port/username; changing that identity requires credentials again. Use the explicit removal options to clear saved material. A new private key with an empty passphrase is treated as an unencrypted replacement key. Host-key changes must be verified before reconnecting.

The SFTP connection negotiates the saved public host key's algorithm. A server offering both RSA and Ed25519 keys can be verified using its saved RSA key; a genuinely different key is rejected before authentication. Authentication failures, missing directories, and directory permission errors have separate messages. The connection test displays a short error popup explaining failures, such as rejected credentials, an incorrect host key, a missing directory, a timeout, or insufficient permissions.

Listings are read-only and search the saved base directory and all its subdirectories for `.csv`/`.CSV` regular files. Relative paths distinguish identical filenames in different folders. File and directory symlinks are not followed. Searches are bounded to 10,000 results, 100,000 examined entries, 5,000 directories and 30 seconds of traversal; the interface marks partial results and explains the limit. Keep the common parent as the saved base path. Listing success confirms access, not that CSV contents conform to an HDR schema. All signed-in users can list files; administrators change source settings.

## 8. GitHub and Argo CD

Store non-secret manifests, image digests, and this guide in Git. For another organization, fork the repository and update the repository URL in your Argo CD Application. The quick-start path is `deploy/kubernetes/quickstart`, target namespace `sbc-console`. Enable namespace creation if Argo CD is responsible for it.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sbc-console
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/hklier/sbc-management-tool.git
    targetRevision: main
    path: deploy/kubernetes/quickstart
  destination:
    server: https://kubernetes.default.svc
    namespace: sbc-console
  syncPolicy:
    automated:
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

If you already used `kubectl` to install, configure Argo CD to adopt the same resources and namespace rather than deploying a second installation over the same data. Keep one active application instance per state volume. Inspect the rendered resources and PVC retention settings before enabling prune. The quick-start PVC carries `Prune=false,Delete=false` for Argo CD.

GitHub Actions validates the application, Kubernetes configuration, and recorder code, and produces a deployable console image artifact. Publish validated images to your registry and commit their digests; Argo CD then reconciles the workload. GitHub-hosted runners do not automatically reach your private cluster or registry.

## 9. Full recording/lab deployment

The existing `deploy/kubernetes/base` profile is a ready-made **lab-specific** full stack with four containers: console, traps, recorder, and transcription. It uses the lab's retained hostPath PV pinned to `k8s-worker2`, a 50 GiB claim, private-registry image digests, and MetalLB address. These values must be reviewed and adapted for another cluster. Do not apply it unchanged to a different environment.

The optional `deploy/configure.py` renderer and `deploy/config.example.yaml` support advanced preconfigured installations. They are not needed by the quick start. Completed private YAML and generated Secrets must stay outside the checkout. The renderer manages application/network/bootstrap settings; it does not configure the SBC. Later GUI edits to users or devices are persistent and are not overwritten by bootstrap values.

Agree retention, recording capacity, RTP port ranges, and SBC SIPREC configuration before enabling live recording. The legacy default retention is intentionally very long; choose a policy appropriate to your deployment. A workload rollout interrupts web sessions and can interrupt active recordings, so schedule upgrades between calls. The app is a single-instance service, not a horizontally scalable recording cluster.

## 10. Backups, recovery, and upgrades

Back up the complete persistent state consistently while the app is stopped, or use a storage snapshot/application-consistent backup method. SQLite can have WAL or rollback-journal files; do not copy only a live `.sqlite3` file and assume it is complete.

Retain these items together:

- User database and related SQLite files.
- Device database, `settings.sqlite3`, and **the matching `device-encryption.key`**.
- The entire `web-tls` directory, including active certificate/private key, pending CSR keys, and `active.json`.
- Audit history, LRT backups, trap database, recordings, transcripts, and any HDR inbox data your retention policy covers.

These backups contain credentials and private keys. Protect access to the volume and backup destination; do not commit state or private files to Git. Losing an encryption key prevents decryption of its saved credentials. Losing a CSR private key requires a new CSR and reissuance. Restore state with ownership/permissions appropriate for UID/GID 10001.

If the default-profile administrator loses access, an authorized cluster administrator can explicitly recover the bootstrap account:

```sh
kubectl -n sbc-console exec deploy/sbc-console -c console -- python users_tools.py --reset-bootstrap
```

With no custom bootstrap hash, this restores **admin / oracle** and requires a password change again. For a legacy preconfigured deployment, it restores the administrator/hash supplied to that running container. Other accounts remain. Run recovery only while controlling endpoint access.

For upgrades, retain the PVC and namespace, back up state, update the image digest in Git, and wait for Argo CD to report **Synced / Healthy**. Verify login, device selection, LRT reading, HDR listing, and the active certificate. The default account is created only when the user database is empty; restarting does not reset a changed password.

## 11. Troubleshooting and acceptance checks

| Symptom | Check |
|---|---|
| PVC stays Pending | Default StorageClass, storage capacity, provisioner events, and ReadWriteOnce support. |
| ImagePullBackOff | Registry address, DNS/routing, image digest/tag, registry TLS, and imagePullSecret. |
| Permission denied at startup | Initializer permission to prepare the application parent directory, UID/GID 10001 access, and NFS export rules; HDR mounts need traversal/read access. |
| Browser certificate warning | Expected initially for the generated self-signed certificate. For a replacement, check SAN coverage, chain, browser CA trust, and where TLS terminates. |
| First login cannot reach Devices/HDR | Complete the mandatory initial password change. |
| Existing installation rejects oracle | Expected after a password change or an upgrade preserving existing accounts. Use the current account credentials. |
| SBC REST fails | Management IP reachability, REST enabled/account permissions, credentials, issuing CA, and IP SAN. |
| LRT/CDR/trace read fails | SFTP access, SSH host-key match, and the actual file/directory on the SBC. A missing CDR directory is an SBC-side prerequisite. |
| HDR SFTP test fails | Saved hostname/port, host key, account authentication, path within chroot, and directory permissions. |
| No HDR CSVs | Files must be direct regular `.csv` files in the saved directory; analysis is not implemented yet. |
| Traps missing | SBC destination/community/version, UDP exposure, source-IP preservation, and device IP matching. |

Useful read-only checks:

```sh
kubectl -n sbc-console get pods,pvc,service
kubectl -n sbc-console describe pod -l app.kubernetes.io/name=sbc-console
kubectl -n sbc-console logs deploy/sbc-console -c console --tail=100
kubectl -n sbc-console logs deploy/sbc-console -c traps --tail=100
```

On a fresh installation, verify the mandatory password change and that the old password stops working. Then check device add/edit/delete with a temporary profile, CSR generation and download, HDR source save and listing, and username-dropdown password/sign-out navigation. Use non-writing previews for live LRT acceptance; do not save or reload production routes just to test deployment.

Reference: [Kubernetes dynamic storage provisioning](https://kubernetes.io/docs/concepts/storage/dynamic-provisioning/), [persistent volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/), and [Python HTTPS certificate loading](https://docs.python.org/3.12/library/ssl.html#ssl.SSLContext.load_cert_chain).
