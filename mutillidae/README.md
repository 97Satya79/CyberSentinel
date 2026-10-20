# OWASP Mutillidae II - Multi-Container Stack

This directory contains the official Docker Compose configuration for running OWASP Mutillidae II alongside MySQL, phpMyAdmin, and OpenLDAP.

## Services & Ports

| Service | Port | Description |
|---|---|---|
| **Mutillidae II Web App** | `http://127.0.0.1:8081` (or `https://127.0.0.1:8443`) | Main vulnerable target application |
| **phpMyAdmin** | `http://127.0.0.1:8082` | MySQL database web administration |
| **phpLDAPadmin** | `http://127.0.0.1:8083` | LDAP directory web administration |
| **OpenLDAP** | `127.0.0.1:389` | LDAP authentication service |
| **MySQL Database** | Internal network only | Backend database for Mutillidae |

---

## Quick Start Commands

### Start Mutillidae Stack
```bash
cd mutillidae
docker compose up -d
```

### Stop Mutillidae Stack
```bash
cd mutillidae
docker compose down
```

### View Logs
```bash
cd mutillidae
docker compose logs -f
```

---

## First-Time Database Setup

1. Open your browser to `http://127.0.0.1:8081`.
2. If you see a database error or setup notification, click **"Setup / Reset Database"** (or navigate to `http://127.0.0.1:8081/set-up-database.php`).
3. Click the button to initialize the database tables. Mutillidae will confirm when the database is created.
4. You are ready to explore and scan!
