# gokev

Go CLI: свежие security advisory из GitHub + каталог CISA KEV, сшитые в один
отчёт. Один статический бинарник, ноль сторонних зависимостей — только stdlib.

Тот же источник данных, что у [cvedigest](https://github.com/doxsir/cvedigest)
и [cvedigest-ui](https://github.com/doxsir/cvedigest-ui), но на Go — нарочно
сделал одно и то же на трёх языках, чтобы честно сравнить подходы.

## Сборка

```bash
go build -o gokev .
./gokev -eco pip -min high -limit 5
```

## Флаги

- `-eco` — экосистема (pip, npm, go, maven...)
- `-min` — минимальная severity (low/moderate/high/critical)
- `-limit` — сколько показать (по умолчанию 10)
- `-json` — машиночитаемый вывод

## Как работает

Два фида (GitHub Advisory + CISA KEV) качаются параллельно горутинами,
результаты сшиваются по CVE ID. Если KEV-фид не скачался — работает без
меток, умирать из-за опциональных данных глупо.
