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
