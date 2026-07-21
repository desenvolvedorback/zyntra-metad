# ZYNTRA — Metadata Intelligence
# Imagem com libmagic (comando `file`) e ffmpeg (ffprobe) para extração
# completa de metadados de imagem, PDF, áudio e vídeo.

FROM python:3.12-slim

# Dependências de sistema:
# - file       -> detecção real de MIME type (libmagic)
# - ffmpeg     -> fornece o ffprobe (metadados de áudio/vídeo)
RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# O Render injeta a variável PORT em tempo de execução.
ENV PORT=10000
EXPOSE 10000

CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 120"]
