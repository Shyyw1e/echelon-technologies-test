# Config Audit

Go-утилита для анализа YAML/JSON-конфигураций веб-приложений и поиска потенциально опасных настроек.

## Возможности

- анализ файла, stdin или директории с конфигами;
- REST API: `POST /analyze`;
- gRPC API: `configaudit.AnalyzerService/Analyze`;
- уровни проблем: `LOW`, `MEDIUM`, `HIGH`;
- ненулевой exit code при найденных проблемах, если не указан `--silent`;
- проверка прав доступа к файлу через `os.Stat`;
- расширяемое ядро правил, общее для CLI, HTTP и gRPC.

## Запуск

```bash
go run ./cmd/config-audit ./config.yaml
go run ./cmd/config-audit --stdin < ./config.yaml
go run ./cmd/config-audit --dir ./configs
go run ./cmd/config-audit --format json ./config.yaml
go run ./cmd/config-audit --silent ./config.yaml
go run ./cmd/config-audit --max-size 2097152 ./config.yaml
```

HTTP-сервер:

```bash
go run ./cmd/config-audit --http :8080
```

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"source_name":"example.yaml","content":"storage:\n  digest-algorithm: MD5\n"}'
```

gRPC-сервер:

```bash
go run ./cmd/config-audit --grpc :9090
```

Контракт лежит в `internal/grpcapi/proto/analyser.proto`. Сервер использует JSON codec поверх gRPC, поэтому клиенту нужно указать gRPC content subtype `json`.

## Флаги

- `-s`, `--silent` - не возвращать ошибочный exit code при найденных проблемах;
- `--stdin` - прочитать конфигурацию из stdin;
- `--dir <path>` - рекурсивно проверить `.json`, `.yaml`, `.yml` файлы;
- `--http <addr>` - запустить REST API сервер;
- `--grpc <addr>` - запустить gRPC сервер;
- `--format text|json` - формат вывода CLI;
- `--max-size <bytes>` - максимальный размер входного конфига.

## Проверяемые правила

- debug/trace logging;
- секреты в открытом виде вместо ссылок на переменные окружения;
- bind на `0.0.0.0` или `::` без явных сетевых ограничений;
- отключенная TLS-проверка;
- слабые алгоритмы: `MD5`, `SHA1`, `DES`, `3DES`, `RC4`, `none`, `RSA1024`;
- слишком широкие права доступа к файлу конфигурации.
