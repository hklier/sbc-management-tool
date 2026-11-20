FROM python:3.12-slim-bookworm AS console
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgomp1 && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home console
WORKDIR /opt/sbc-console
COPY app/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app/ ./
COPY deploy/healthcheck.py /opt/healthcheck.py
RUN mkdir -p /var/lib/sbc-console/recordings && chown -R 10001:10001 /var/lib/sbc-console
USER 10001:10001
CMD ["python", "server.py"]

FROM console AS transcription
USER root
RUN pip install --no-cache-dir faster-whisper==1.1.1 ctranslate2==4.5.0 numpy==1.26.4 av==12.3.0 huggingface-hub==0.28.1
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('Systran/faster-whisper-tiny', revision='d90ca5fe260221311c53c58e660288d3deb8d356', local_dir='/opt/sbc-transcription/model', allow_patterns=['config.json','model.bin','tokenizer.json','vocabulary.*','preprocessor_config.json'])"
ENV TRANSCRIPTION_PYTHON=/usr/local/bin/python TRANSCRIPTION_MODEL=/opt/sbc-transcription/model HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
USER 10001:10001
CMD ["python", "transcription_worker.py"]

FROM golang:1.27.3-alpine AS go-builder
WORKDIR /build
COPY siprec/go.mod siprec/go.sum ./
RUN go mod download && go mod verify
COPY siprec/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /siprec ./cmd/siprec

FROM console AS recorder
COPY --from=go-builder /siprec /opt/siprec-runtime/siprec
ENV SIPREC_WORKDIR=/opt/sbc-console
CMD ["python", "recordings_supervisor.py"]
