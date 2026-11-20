#!/usr/bin/env bash
# Run on a trusted Linux build host that can reach the LAN registry.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?Usage: bash deploy/build-release.sh VERSION}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || { echo 'Use a version such as 0.1.1'; exit 2; }
registry="${REGISTRY:-192.168.2.240:5000/sbc-management-tool}"
runtime="${CONTAINER_RUNTIME:-podman}"
tls_verify="${REGISTRY_TLS_VERIFY:-false}"
for target in console recorder transcription; do
  "$runtime" build --layers --target "$target" -f deploy/Dockerfile -t "$registry/$target:$version" .
done
"$runtime" run --rm --user 0 --tmpfs /var/lib/sbc-console --tmpfs /tmp "$registry/console:$version" python -m unittest discover -s /opt/sbc-console -p 'test_*.py'
"$runtime" build --layers --target go-builder -f deploy/Dockerfile -t sbc-management-tool-go-tests .
"$runtime" run --rm -e CGO_ENABLED=0 sbc-management-tool-go-tests go test ./pkg/siprec ./pkg/sip -run 'TestOracle|TestHandleSiprecReInviteUpdatesSession' -count=1
temporary="$(mktemp -d)"
trap 'rm -f "$temporary"/*.digest; rmdir "$temporary"' EXIT
for target in console recorder transcription; do
  "$runtime" push --tls-verify="$tls_verify" --digestfile "$temporary/$target.digest" "$registry/$target:$version"
done
python3 - "$registry" "$temporary" <<'PY'
from pathlib import Path
import json,sys
registry,directory=sys.argv[1:]
path=Path('deploy/kubernetes/base/kustomization.yaml')
data=json.loads(path.read_text())
for image in data['images']:
    target=image['name'].replace('sbc-','')
    image['newName']=registry+'/'+target
    image.pop('newTag',None)
    image['digest']=(Path(directory)/(target+'.digest')).read_text().strip()
path.write_text(json.dumps(data,indent=2)+'\n')
PY
echo 'Images published. Review and commit deploy/kubernetes/base/kustomization.yaml, then push to main for Argo CD.'
