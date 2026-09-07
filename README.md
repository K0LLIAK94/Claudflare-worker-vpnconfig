# Cloudflare Worker VPN subscription bridge

Cloudflare Worker для объединения TXT-подписок из `igareck/vpn-configs-for-russia` в одну подписку для Throne и совместимых VPN-клиентов.

## Что делает Worker

- Отдаёт `/subscription` в формате `base64` по умолчанию.
- Поддерживает `?format=plain` для обычного построчного TXT.
- Поддерживает области `scope=all`, `scope=black`, `scope=white-cidr`, `scope=white-sni`.
- Проверяет SHA последнего коммита upstream-репозитория.
- Если SHA не изменился, отдаёт готовую подписку из Cloudflare KV.
- Если SHA изменился, скачивает TXT-файлы с GitHub, объединяет их, удаляет точные дубликаты и сохраняет новую версию в KV.
- Если GitHub временно недоступен, продолжает отдавать последнюю успешную подписку из KV.
- `/status` показывает состояние кэша и не пересобирает подписку без необходимости.

## Cloudflare bindings

Для новой версии нужны два binding:

1. KV namespace:
   - binding name: `SUBSCRIPTIONS_KV`

2. Durable Object:
   - binding name: `UPDATE_LOCK`
   - class name: `UpdateLock`

Durable Object нужен, чтобы несколько одновременных запросов не запускали параллельную сборку одной и той же подписки.

## URL

```text
https://<worker>.<subdomain>.workers.dev/subscription?scope=all
https://<worker>.<subdomain>.workers.dev/subscription?scope=all&format=plain
https://<worker>.<subdomain>.workers.dev/status?scope=all
```

## Рекомендуемый режим

Если конфиги upstream появляются каждые 1–3 часа, оптимально оставить проверку SHA раз в 15 минут. VPN-клиент может обновлять подписку раз в 60 минут.
