# Auth Services (Django + Docker)

A scalable Authentication Service built with **Django Rest Framework**, **PostgreSQL**, **Redis**, and **Nginx**, fully containerized using **Docker**.

## 🚀 Tech Stack

* **Backend:** Python 3.13, Django 5.x, Django Rest Framework
* **Database:** PostgreSQL 15
* **Cache/Queue:** Redis 7
* **Web Server:** Nginx (Reverse Proxy)
* **Containerization:** Docker & Docker Compose
* **Package Manager:** uv

## 📂 Project Structure

```text
.
├── config/             # Django project configuration & settings
│   ├── settings/       # Split settings (base, local, production)
│   └── ...
├── docker/             # Dockerfiles and entrypoints
├── pg_data/            # Database persistence (GitIgnored)
├── static/             # Collected static files (GitIgnored)
├── media/              # User uploads (GitIgnored)
├── docker-compose.yml  # Service orchestration
├── .env                # Environment variables (GitIgnored)
└── README.md
```