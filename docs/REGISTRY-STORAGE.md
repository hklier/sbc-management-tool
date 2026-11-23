# Registry storage and recovery

The lab image registry at `192.168.2.240:5000` uses shared NFS storage. Its image data no longer depends on the worker that runs the registry pod. The NFS server must remain available when the cluster restarts.

## Storage layout

- Namespace and Deployment: `registry`
- Claim: `registry-storage-shared`, 50 GiB, `ReadWriteMany`
- StorageClass: `registry-nfs-retain`, backed by the existing NFS CSI driver
- Reclaim policy: `Retain`
- Registry directory on the claim: `data/`
- Migration snapshots: `migration-backups/`
- Checksums and validation reports: `migration-reports/`

The deployment runs one registry replica with the `Recreate` update strategy. Both the registry and its startup check use the existing runtime pinned to its public image digest, so starting the registry does not require pulling its own image from the private registry.

The startup check requires the expected `.registry-volume-id` file and image directory. It refuses to serve a newly provisioned empty volume in place of the migrated data. The deployment has no worker selector.

The claim has Argo CD `Prune=false,Delete=false` protection. The StorageClass and actual bound volume use `Retain`, preserving the storage if a claim is accidentally removed. Retention does not automatically rebind a replacement claim: an administrator must recover the retained volume. Do not delete and recreate the claim as a troubleshooting step.

## Declarative configuration

The existing-cluster configuration is in `deploy/registry/`. It is separate from the SBC application's Kustomize directory: installing the application does not create or replace a registry.

Before applying it to another cluster, provide an NFS CSI StorageClass named `registry-nfs-retain` with your NFS server, share, and `reclaimPolicy: Retain`. Adapt the service address and restore the image data and matching volume marker first. These manifests describe the migrated lab registry; they are not an empty-registry installer.

```sh
kubectl apply --dry-run=server -k deploy/registry
kubectl apply -k deploy/registry
kubectl rollout status deployment/registry -n registry
kubectl get pvc -n registry
```

To manage this directory through Argo CD, use a separate Application and preserve the existing namespace and claim. Do not enable force replacement of the PVC. Keep the NFS StorageClass under cluster administration so deleting an application cannot remove shared storage configuration.

## Backups and restart behavior

A registry pod restart or move to another worker mounts the same NFS claim. A cluster restart also uses the same claim and external NFS data. If NFS is unavailable, restore NFS connectivity before restarting application workloads that need new image pulls.

Back up the NAS dataset, including the registry data and migration reports, to a separate system. The migration snapshots are on the same NAS and therefore do not protect against NAS disk loss. For a consistent filesystem backup, stop registry writes or scale the registry to zero for the snapshot, then restore its replica count to one.

The previous node-local claim, `registry-storage`, and its retained volume remain available for emergency recovery. Its data differs by worker. The pre-migration live registry was on `k8s-worker1`; the older image set was on `k8s-worker2`. A rollback to a node-local claim must pin the registry to the correct worker. Private original resource snapshots and a worker-pinned rollback deployment are kept in the operator's `deployment-private/registry-storage-migration/` directory. Using that rollback would hide images pushed after migration; preserve the shared dataset before doing so.

## Validation

The migration checksums each copied file, verifies stored blob digests, and checks manifest references before starting the registry on shared storage. Current tag mappings take priority over older copies. Older conflicting tags receive a `.recovered-worker2-<digest>` suffix rather than overwriting the current image.

Record post-migration inventory checks, node movement, pod recreation, and image push/pull checks in the private migration report. A successful node-movement check is stronger evidence than a bound PVC alone. A full cluster reboot is not required to perform this check.

The 23 November 2026 migration recovered 42 image tags across 11 repositories and validated 44 manifest revisions. All five previously visible tags kept their original digests. The registry was started on worker1, moved to worker2, and recreated with its worker selector removed. A new verification image was pushed and pulled successfully by jobs on both workers. The resulting 43-tag inventory, including the verification image, remained unchanged after pod recreation. No full cluster reboot was performed.

## References

- [Kubernetes persistent volumes and reclaiming](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [Kubernetes StorageClasses](https://kubernetes.io/docs/concepts/storage/storage-classes/)
- [Distribution filesystem storage driver](https://distribution.github.io/distribution/storage-drivers/filesystem/)
