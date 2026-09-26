# gokev

Go CLI: свежие security advisory из GitHub + каталог CISA KEV, сшитые в один
отчёт. Один статический бинарник, ноль сторонних зависимостей — только stdlib.

Тот же источник данных, что у [cvedigest](https://github.com/doxsir/cvedigest)
(Python CLI) и [cvedigest-ui](https://github.com/doxsir/cvedigest-ui)
(React-дашборд) — нарочно сделал одно и то же на трёх языках, чтобы честно
сравнить подходы. Спойлер: для CLI с одним бинарником Go выигрывает.

## Скачивание

Готовые бинарники — в [releases](https://github.com/doxsir/gokev/releases)
(linux/windows amd64, статические, без зависимостей). Или собери сам:

```bash
go build -o gokev .
```

## Использование

```bash
./gokev -eco pip -min high -limit 5
./gokev -kev                    # только то, что в CISA KEV
./gokev -json                   # машиночитаемый вывод
```

- `-eco` — экосистема (pip, npm, go, maven...)
- `-min` — минимальная severity (low/moderate/high/critical)
- `-limit` — сколько показать (по умолчанию 10)
- `-json` — JSON вместо текста

## Как работает

Два фида (GitHub Advisory + CISA KEV) качаются **параллельно горутинами**,
результаты сшиваются по CVE ID. Если KEV-фид не скачался — работает без
меток, умирать из-за опциональных данных глупо. Тесты покрывают фильтры
severity и KEV.
