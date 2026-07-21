# ZYNTRA — Metadata Intelligence

Ferramenta OSINT para extração de metadados de qualquer tipo de arquivo.
100% local: sem banco de dados, sem IA, sem envio de dados para terceiros.
Cada análise roda em memória / arquivo temporário e é apagada logo em seguida.

## Como rodar

```bash
pip install -r requirements.txt --break-system-packages   # ou use um venv
python3 app.py
```

Abra `http://localhost:5000` no navegador.

## Dependências externas usadas pelo sistema (não-Python)

- `file` (libmagic) — detecção real de MIME type
- `ffprobe` (parte do FFmpeg) — metadados de áudio e vídeo

Ambas já vêm instaladas na maioria das distros Linux. Se `ffprobe` não
estiver disponível, os campos de Áudio/Vídeo simplesmente não aparecem
(o resto da ferramenta continua funcionando normalmente).

## O que é extraído

- **Resumo do arquivo**: nome, MIME real, tamanho, hashes, entropia, indicador de risco
- **Hashes**: MD5, SHA1, SHA224/256/384/512, SHA3-256/512, BLAKE2b/2s, CRC32
- **Imagens**: EXIF completo (fabricante, modelo, lente, ISO, exposição, GPS, cor
  dominante, ICC, etc.) via Pillow
- **PDF**: autor, produtor, datas, páginas, criptografia, JavaScript embutido,
  URLs, AcroForm, assinaturas digitais (via pikepdf + varredura binária)
- **Office** (docx/xlsx/pptx): autor, empresa, revisões, detecção de macros VBA
- **Áudio/Vídeo**: codec, bitrate, resolução, FPS, tags ID3/metadata (via ffprobe)
- **ZIP/APK**: estrutura interna, hashes por arquivo, libs nativas, assinatura APK
- **Executáveis** (PE/ELF/Mach-O): arquitetura, timestamp de compilação, seções
  (parsing manual de headers)
- **Certificados digitais**: X.509 embutidos (via `cryptography`)
- **Strings/OSINT**: e-mails, IPs, domínios, URLs, JWT, chaves de API, UUIDs
- **Hex viewer** com busca
- **GPS**: coordenadas + mapa embutido (OpenStreetMap)

## Exportação

TXT, JSON, CSV, HTML e PDF (via impressão do navegador), tudo gerado no
próprio navegador — nada é salvo no servidor.

## Estrutura

```
zyntra/
├── app.py               → backend Flask + toda a lógica de extração
├── templates/index.html → interface (com JS embutido)
└── static/style.css     → tema escuro azul neon
```
# ZYNTRA — Metadata Intelligence

Ferramenta OSINT para extração de metadados de qualquer tipo de arquivo.
100% local: sem banco de dados, sem IA, sem envio de dados para terceiros.
Cada análise roda em memória / arquivo temporário e é apagada logo em seguida.

## Como rodar

```bash
pip install -r requirements.txt --break-system-packages   # ou use um venv
python3 app.py
```

Abra `http://localhost:5000` no navegador.

## Dependências externas usadas pelo sistema (não-Python)

- `file` (libmagic) — detecção real de MIME type
- `ffprobe` (parte do FFmpeg) — metadados de áudio e vídeo

Ambas já vêm instaladas na maioria das distros Linux. Se `ffprobe` não
estiver disponível, os campos de Áudio/Vídeo simplesmente não aparecem
(o resto da ferramenta continua funcionando normalmente).

## O que é extraído

- **Resumo do arquivo**: nome, MIME real, tamanho, hashes, entropia, indicador de risco
- **Hashes**: MD5, SHA1, SHA224/256/384/512, SHA3-256/512, BLAKE2b/2s, CRC32
- **Imagens**: EXIF completo (fabricante, modelo, lente, ISO, exposição, GPS, cor
  dominante, ICC, etc.) via Pillow
- **PDF**: autor, produtor, datas, páginas, criptografia, JavaScript embutido,
  URLs, AcroForm, assinaturas digitais (via pikepdf + varredura binária)
- **Office** (docx/xlsx/pptx): autor, empresa, revisões, detecção de macros VBA
- **Áudio/Vídeo**: codec, bitrate, resolução, FPS, tags ID3/metadata (via ffprobe)
- **ZIP/APK**: estrutura interna, hashes por arquivo, libs nativas, assinatura APK
- **Executáveis** (PE/ELF/Mach-O): arquitetura, timestamp de compilação, seções
  (parsing manual de headers)
- **Certificados digitais**: X.509 embutidos (via `cryptography`)
- **Strings/OSINT**: e-mails, IPs, domínios, URLs, JWT, chaves de API, UUIDs
- **Hex viewer** com busca
- **GPS**: coordenadas + mapa embutido (OpenStreetMap)

## Exportação

TXT, JSON, CSV, HTML e PDF (via impressão do navegador), tudo gerado no
próprio navegador — nada é salvo no servidor.

## Deploy no Render

Duas opções — a primeira é a recomendada porque preserva 100% das
funcionalidades.

### Opção A — Docker (recomendado, todas as features)

O projeto já inclui um `Dockerfile` pronto (instala `file`/libmagic e
`ffmpeg`, que o Render **não** oferece no ambiente nativo Python).

No painel do Render:
1. New → Web Service → conecte o repositório do GitHub
2. Em **Environment**, escolha **Docker** (o Render detecta o `Dockerfile`
   automaticamente na raiz do repo — não precisa preencher Build/Start Command)
3. **Instance Type**: Free ou Starter já funciona
4. Deploy

O container já escuta na porta que o Render define via `$PORT`
automaticamente (configurado no `CMD` do Dockerfile).

### Opção B — Ambiente nativo Python (mais simples, com uma limitação)

No painel do Render:
1. New → Web Service → conecte o repositório
2. **Environment**: Python 3
3. **Build Command**:
   ```
   pip install -r requirements.txt
   ```
4. **Start Command**:
   ```
   gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120
   ```

Limitação desta opção: o ambiente nativo do Render não permite instalar
pacotes de sistema via `apt-get`. Sem os binários `file` e `ffprobe`, a
ferramenta continua funcionando normalmente, mas:
- o **tipo MIME real** cai para detecção básica por extensão em vez da
  libmagic completa;
- as abas de **Áudio** e **Vídeo** não aparecem (dependem do `ffprobe`).

Tudo o resto (hashes, EXIF/GPS, PDF, Office, ZIP/APK, executáveis,
certificados, strings, hex) funciona igual nas duas opções.

### Aumentar o limite de upload (opcional)

O limite atual é 300MB, definido em `app.py`
(`app.config["MAX_CONTENT_LENGTH"]`). Ajuste esse valor se precisar de
mais ou menos.


## Estrutura

```
zyntra/
├── app.py               → backend Flask + toda a lógica de extração
├── templates/index.html → interface (com JS embutido)
├── static/style.css     → tema escuro azul neon
├── requirements.txt     → dependências Python
├── Dockerfile           → deploy com libmagic + ffmpeg (Render/qualquer PaaS)
└── .dockerignore
```
