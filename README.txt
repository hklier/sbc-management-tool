SBC CONSOLE - SOURCE HANDOFF
============================

This package contains the current web console source and the locally patched
SIPREC recorder source. Give the entire ZIP to the colleague responsible for
GitHub and Kubernetes. Start with CONFIGURATION.txt to set the target SBC and
credentials. All placeholders must be replaced in the deployment environment.

CONTENTS
app/                    Python application, browser UI, tests and service files
siprec/                 Patched Go recorder source, upstream license and tests
environment.example     Console configuration template; no working credentials
CONFIGURATION.txt       SBC address, credentials, HTTPS, SSH and SNMP settings
SOURCE-MANIFEST.json     SHA-256 hashes of packaged files

The package excludes local application state, SBC configuration backups,
captured traffic, operational recordings, trap databases and live environment
files. The upstream SIPREC source retains its own example configurations and
test fixtures, including test certificates; these are not deployment secrets
and must not be used as production certificates. Example lab addresses in
existing documentation are historical examples, not required deployment values.

GITHUB HANDOFF
Create a repository and commit the extracted directory, including its ignore
files. Choose repository visibility with the owner before publishing. Keep real
environment files, passwords, tokens, keys and runtime data outside Git. Retain
the SIPREC GPL-3.0 license and attribution, and review dependency licenses for
the intended distribution. The repository has not been created or published.

CURRENT RUNTIME
The web console is Python 3.12 with dependencies in app/requirements.txt. Its
entrypoint is app/server.py; static assets must remain alongside that file.
Existing Linux service files document paths and process separation. install.sh
assumes an already provisioned Python runtime and private environment, and has
lab-specific certificate values. It is not a complete fresh-server installer.

The recorder is based on https://github.com/loreste/siprec at revision
994b9d4c34be89df443da5818bdb485bff4e865c. The source under siprec/ ALREADY contains
the console integration and Oracle compatibility fixes. Do not reapply the
patch files under app/ to this embedded source. Those patches document changes
relative to upstream. Build for the target architecture, for example:

  cd siprec
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o siprec ./cmd/siprec

The current deployed build used Go 1.27.3. app/SIPREC-SOURCE.txt records its
identity and app/siprec-recorder.env.example documents recorder configuration.
Recording uses PCMU/PCMA and plain SIP/RTP with the current tested profile.
Review the environment for the deployment network instead of copying lab IPs.

Offline transcription is a separate Python worker. See app/TRANSCRIPTION.txt
and app/transcription-wheels.json. Its engine is faster-whisper 1.1.1 with
CTranslate2 4.5.0. Download the multilingual tiny model from
https://huggingface.co/Systran/faster-whisper-tiny at revision
d90ca5fe260221311c53c58e660288d3deb8d356. Binaries, Python runtimes, dependency
wheels and model files are not bundled. Provision them during the image build
or deployment. Do not enable upstream mock/cloud STT as a substitute for the
separate local worker. Run only one transcription job at a time initially.

KUBERNETES WORK STILL REQUIRED
This is a source handoff, not a tested Kubernetes deployment of the console.
Upstream recorder Docker/deployment examples do not deploy the integrated web
console and its workers. The colleague should:

1. Build container images for the web console, recorder, transcription worker
   and trap receiver, replacing the current systemd entrypoints as appropriate.
2. Supply non-secret configuration through a ConfigMap and credentials through
   Secrets or the organization's external secret provider. Mount certificates
   and model files where configured. See CONFIGURATION.txt for exact settings.
3. Mount persistent writable storage for STATE_DIR and the shared recordings
   directory. The console, recorder and transcription worker need consistent
   paths and permissions. Start with one instance of each process. Console
   sessions, SBC tokens and locks are in memory; the SQLite trap database and
   filesystem processing are not designed for a multiwriter HA deployment.
4. Adapt trap_tools.py to bind UDP directly, or provide a compatible inherited
   socket launcher. It currently requires systemd socket activation and will
   not start by simply running python trap_tools.py in a container.
5. Review hardcoded /opt and /var/lib paths in service files, the recorder
   supervisor and transcription worker. Configure or mount matching paths.
6. Expose HTTPS for the console and route SIP, RTP and traps separately. The
   current server rejects network binding without its own TLS certificate;
   an ingress that only terminates TLS externally needs an explicit backend
   TLS arrangement or an application change reviewed and tested for that use.
7. Plan a stable SIPREC advertised/reachable address and route SIP and RTP to
   the same recorder. Current lab ports are SIP 5060 UDP/TCP, RTP 30000-30199
   UDP and traps 162 UDP. The RTP range overlaps the default Kubernetes
   NodePort range; validate or change the port plan. HTTP ingress alone does
   not provide the required SIP/RTP routing. SBC connections also require
   outbound HTTPS 443, SFTP 22 and SNMP UDP 161 (or configured alternatives).
8. Set resource requests/limits and validate persistent storage, shutdown,
   permissions, firewall/SELinux policy, audio and backup/retention behavior.

Official references:
https://kubernetes.io/docs/concepts/services-networking/service/
https://kubernetes.io/docs/reference/networking/service-protocols/
https://kubernetes.io/docs/reference/networking/ports-and-protocols/
https://kubernetes.io/docs/concepts/configuration/secret/

ACCEPTANCE CHECKS AFTER MIGRATION
Log in; browse SBC configuration and CDR details; read LRTs and PCAP flows;
query SNMP; receive a test trap; record a test call with both audio directions
and transcription; restart processes and confirm persisted data remains.
Only test configuration writes/save/activate with the SBC owner's approval.
The REST activity viewer deliberately displays authentication values and tokens
to authenticated console users, as requested for this app. Account for this
when assigning access and sharing screenshots or diagnostic exports.
