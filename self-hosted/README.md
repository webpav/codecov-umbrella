# Codecov Self-Hosted Docker Compose

Этот docker-compose файл позволяет собрать и запустить Codecov self-hosted из исходного кода с поддержкой SSL.

## Особенности

- Собирает контейнеры из исходного кода (API, Worker)
- Использует существующие Dockerfile'ы из проекта
- Настроен для self-hosted окружения с SSL
- Настроен для домена codecov.karamba.cloud
- Включает все необходимые зависимости (PostgreSQL, TimescaleDB, Redis, MinIO)

## Подготовка

1. Убедитесь, что у вас есть конфигурационные файлы в директории `./config/`

2. Убедитесь, что у вас есть SSL сертификат в `./cert/nginx-selfsigned.crt` или настройте переменную окружения `CODECOV_SSL_CERT`

## Запуск

1. Соберите и запустите все сервисы:
   ```bash
   docker-compose up --build
   ```

2. Для запуска в фоновом режиме:
   ```bash
   docker-compose up --build -d
   ```

## Доступ к сервисам

- **Codecov Web UI**: https://codecov.karamba.cloud (порт 443)
- **MinIO API**: http://localhost:9000
- **PostgreSQL**: внутренний доступ через сеть codecov
- **TimescaleDB**: внутренний доступ через сеть codecov
- **Redis**: внутренний доступ через сеть codecov

## Управление

- Остановка всех сервисов:
  ```bash
  docker-compose down
  ```

- Пересборка конкретного сервиса:
  ```bash
  docker-compose build api
  docker-compose up api
  ```

- Просмотр логов:
  ```bash
  docker-compose logs -f api
  docker-compose logs -f worker
  ```

## Переменные окружения

- `CODECOV_SSL_CERT`: Путь к SSL сертификату (по умолчанию: `./cert/nginx-selfsigned.crt`)
- `CODECOV_SSL_PORT`: SSL порт (по умолчанию: 443)
- `CODECOV_MINIO_PORT`: Порт MinIO (по умолчанию: 9000)

## Структура сервисов

- **requirements**: Базовый образ с зависимостями Python (собирается из кода)
- **gateway**: Шлюз для маршрутизации запросов (предсобранный образ)
- **frontend**: Веб-интерфейс (предсобранный образ)
- **api**: Codecov API сервер (собирается из кода)
- **worker**: Codecov Worker для обработки задач (собирается из кода)
- **postgres**: Основная база данных
- **timescale**: База данных для временных рядов
- **redis**: Брокер сообщений и кэш
- **minio**: S3-совместимое хранилище

## Примечания

- API и Worker контейнеры собираются из исходного кода при первом запуске
- Конфигурационные файлы монтируются из `./config/`
- Данные баз данных и хранилища сохраняются в Docker volumes
- Используется сеть `codecov` для связи между контейнерами
- Настроен для работы с SSL и доменом codecov.karamba.cloud
- Базы данных настроены с тестовыми паролями (измените в production)
