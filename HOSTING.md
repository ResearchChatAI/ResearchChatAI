# Hosting ResearchChatAI on Your Own Server

This guide walks you through setting up ResearchChatAI on a Linux server with Apache, MySQL, PHP, and Node.js.

The examples use Apache and `systemd` on a Debian/Ubuntu-style system. Other setups (for example nginx, or a shared host with a process supervisor) work just as well. What matters is that PHP can serve the site, a small Node.js process is running, and the web server forwards one path to it (see [Step 5](#5-configure-apache-as-a-reverse-proxy)).

---

## Prerequisites

| Software   | Minimum Version | Purpose                          |
|------------|-----------------|----------------------------------|
| Apache     | 2.4+            | Web server for PHP + reverse proxy |
| PHP        | 8.0+            | Backend logic                    |
| MySQL      | 8.0+ (or MariaDB) | Database                       |
| Node.js    | 14+             | Streaming proxy for AI responses |

**Required Apache modules:** `mod_rewrite`, `mod_proxy`, `mod_proxy_http`

**Required PHP extensions:** `pdo_mysql`, `mbstring`, `openssl`, `sodium`, `curl`, `zip`

---

## 1. Directory Structure

The project expects the `.env` file to sit **one directory above** the web-accessible document root. This keeps secrets out of reach of the web server.

```
/var/www/researchchatai/
├── .env                          <-- environment config (NOT web-accessible)
└── public_html/                  <-- Apache DocumentRoot
    ├── index.php
    ├── chat.php
    ├── login.php
    ├── signup.php
    ├── Backend/
    │   ├── Chat/
    │   │   ├── prepareChat.php
    │   │   ├── saveResponse.php
    │   │   └── stream-proxy.js   <-- Node.js server
    │   ├── MySQL/
    │   └── Util/
    ├── Uploads/                  <-- create this yourself (not in the repo)
    └── src/
```

1. Clone or copy the project files into `public_html/` (or whatever your Apache document root is).
2. Place the `.env` file one level above that directory (see Step 3).
3. Create the empty `Uploads/` directory inside `public_html/`. Participant image uploads are stored there.

---

## 2. Create the MySQL Database

```sql
CREATE DATABASE researchchatai
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER 'rcai_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON researchchatai.* TO 'rcai_user'@'localhost';
FLUSH PRIVILEGES;
```

Then import the database schema. The schema is not yet included in this repository; please contact the maintainers to obtain the `.sql` file.

> **MySQL 8 vs. MariaDB:** some `TEXT` columns in the schema have default values. MariaDB accepts them as written. MySQL 8 requires the default to be wrapped in parentheses, e.g. `DEFAULT ('x')` instead of `DEFAULT 'x'`.

---

## 3. Configure the `.env` File

The repository contains an empty `.env` template in its root folder. Copy it one level up, fill in your values, and remove the template from the web root:

```bash
cd /var/www/researchchatai
cp public_html/.env .env
nano .env
rm public_html/.env
```

### Database

```env
DB_DATABASE=researchchatai
DB_SERVER=localhost
DB_USERNAME=rcai_user
DB_PASSWORD=your-strong-password
DB_CHARSET=utf8mb4
DB_COLLATE=utf8mb4_unicode_ci
```

### Application

```env
BASE_URL=https://yourdomain.com/
ENCRYPTION_KEY=a-long-random-string-here
```

- `BASE_URL` — the full URL where your site is accessible (include trailing slash).
- `ENCRYPTION_KEY` — used to encrypt sensitive study data. Generate one with:
  ```bash
  openssl rand -hex 32
  ```

### Stream Proxy (Node Server)

```env
STREAM_CONFIG_DIR=/var/www/researchchatai/stream_configs
```

This is a shared temp directory where PHP writes one-time config files and the Node proxy reads them. **This value must be set, and both PHP and Node must have read/write access to this directory.** More on this in Steps 4 and 6.

### Email (SMTP)

```env
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=you@yourdomain.com
SMTP_PASS=your-smtp-password
SMTP_FROM=noreply@yourdomain.com
SMTP_FROMNAME="ResearchChatAI"
```

Used for password reset emails and notifications.

Encryption is chosen automatically from the port: `465` uses implicit TLS (SMTPS), `587` uses STARTTLS. For any other port you can set it explicitly with `SMTP_SECURE=tls` or `SMTP_SECURE=ssl`.

### Cloudflare Turnstile (Captcha)

```env
TURNSTILE_SITE_KEY=your-site-key
TURNSTILE_SECRET_KEY=your-secret-key
```

Sign up at [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/) to get these keys. Used on signup/login forms to prevent bots.

### AI Provider API Keys (Optional)

```env
OPENAI_API=sk-...
OPENROUTER_API=sk-or-...
```

These keys are **not needed to run the application**. Researchers enter their own API keys for each study. The keys in `.env` are only used by optional maintenance scripts (system checks and load tests).

---

## 4. Set Up the Node.js Streaming Proxy

The file `Backend/Chat/stream-proxy.js` is a zero-dependency Node.js server. It handles long-lived streaming connections to AI providers so PHP workers are freed quickly.

### How it works

1. **PHP** (`prepareChat.php`) receives a chat message, writes the AI request config to a temp JSON file in `STREAM_CONFIG_DIR`, and returns a one-time token to the browser.
2. **Node** (`stream-proxy.js`) receives the token from the browser, reads and deletes the config file, then opens a streaming connection to the AI provider and pipes the response back.
3. **PHP** (`saveResponse.php`) receives the completed response from the browser and saves it to the database.

API keys never touch the browser — they only exist in the temp config file on disk.

### Start the Node server

```bash
cd /var/www/researchchatai/public_html/Backend/Chat

# Set the shared config directory (must match .env STREAM_CONFIG_DIR)
export STREAM_CONFIG_DIR=/var/www/researchchatai/stream_configs

# Start the proxy (default port: 9222)
node stream-proxy.js
```

#### Environment variables for the Node server

| Variable              | Default                    | Description                        |
|-----------------------|----------------------------|------------------------------------|
| `STREAM_PROXY_PORT`   | `9222`                     | Port the proxy listens on          |
| `STREAM_PROXY_HOST`   | `0.0.0.0`                  | Host/interface to bind to          |
| `STREAM_CONFIG_DIR`   | *(none, required)*         | Shared config directory with PHP   |
| `STREAM_TOKEN_MAX_AGE`| `120`                      | Token expiry in seconds            |
| `STREAM_CORS_ORIGINS` | `*`                        | Allowed CORS origins (comma-separated) |

`STREAM_CONFIG_DIR` has no default in the Node server and must be set to exactly the same path as in `.env`.

### Keep it running with systemd

Create `/etc/systemd/system/rcai-stream.service`:

```ini
[Unit]
Description=ResearchChatAI Stream Proxy
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/researchchatai/public_html/Backend/Chat
ExecStart=/usr/bin/node stream-proxy.js
Restart=always
RestartSec=5

Environment=STREAM_CONFIG_DIR=/var/www/researchchatai/stream_configs
Environment=STREAM_PROXY_PORT=9222
Environment=STREAM_CORS_ORIGINS=https://yourdomain.com

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable rcai-stream
sudo systemctl start rcai-stream

# Check status
sudo systemctl status rcai-stream

# View logs
sudo journalctl -u rcai-stream -f
```

---

## 5. Configure Apache as a Reverse Proxy

The browser calls `https://yourdomain.com/Backend/Chat/stream` for streaming. Apache must forward this specific path to the Node proxy running on port 9222.

### Enable required modules

```bash
sudo a2enmod proxy proxy_http rewrite
sudo systemctl restart apache2
```

### VirtualHost configuration

Add these lines inside your `<VirtualHost>` block (e.g., `/etc/apache2/sites-available/yourdomain.conf`):

```apache
<VirtualHost *:443>
    ServerName yourdomain.com
    DocumentRoot /var/www/researchchatai/public_html

    # ... your existing SSL config ...

    # Reverse proxy: forward /Backend/Chat/stream to the Node server
    ProxyPreserveHost On
    ProxyPass        "/Backend/Chat/stream" "http://127.0.0.1:9222/Backend/Chat/stream"
    ProxyPassReverse "/Backend/Chat/stream" "http://127.0.0.1:9222/Backend/Chat/stream"

    # Disable buffering for streaming (SSE) responses
    <Location "/Backend/Chat/stream">
        SetEnv proxy-sendchunked 1
        SetEnv proxy-nokeepalive 1
    </Location>

    <Directory /var/www/researchchatai/public_html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

Then reload Apache:

```bash
sudo systemctl reload apache2
```

### Installing in a subdirectory

If the site runs under a path such as `https://yourdomain.com/researchchat/`, set `BASE_URL` to that full URL and proxy `/researchchat/Backend/Chat/stream` instead. The Node proxy accepts any request path that ends in `/stream`.

### Using nginx instead of Apache

The equivalent nginx configuration is:

```nginx
location = /Backend/Chat/stream {
    proxy_pass http://127.0.0.1:9222;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_buffering off;          # required for streaming responses
    proxy_read_timeout 300s;
}
```

---

## 6. Directory Permissions

```bash
# Create the shared stream config directory and the Uploads directory
sudo mkdir -p /var/www/researchchatai/stream_configs
sudo mkdir -p /var/www/researchchatai/public_html/Uploads

# Make the Uploads directory writable
sudo chown -R www-data:www-data /var/www/researchchatai/public_html/Uploads
sudo chown -R www-data:www-data /var/www/researchchatai/stream_configs

# Restrict permissions (only the web user needs access)
sudo chmod 700 /var/www/researchchatai/stream_configs
sudo chmod 755 /var/www/researchchatai/public_html/Uploads
```

The Node service and PHP must run as the **same user** (or a user in the same group) so both can read/write the `stream_configs` directory. If you used `www-data` in the systemd service (as shown above), this matches Apache's default user.

---

## 7. Verify Everything Works

### Check the Node proxy health endpoint

```bash
curl http://127.0.0.1:9222/health
```

Expected response:

```json
{"ok":true,"activeStreams":0,"uptime":42}
```

### Check the proxy through Apache

```bash
curl -X POST https://yourdomain.com/Backend/Chat/stream \
  -H "Content-Type: application/json" \
  -d '{"requestToken":"invalid"}'
```

Expected response (proves Apache correctly forwards to Node):

```json
{"error":"Invalid or missing requestToken"}
```

If you get a `404` or Apache error page instead, the reverse proxy is not configured correctly.

### Test end-to-end

1. Open `https://yourdomain.com/login.php` and sign up for an account.
2. Create a study with an AI provider and API key.
3. Open the study's chat link in a new browser tab.
4. Send a message — you should see a streaming AI response.

---

## Quick Troubleshooting

| Problem | Check |
|---------|-------|
| Chat sends but no response appears | Is the Node server running? Check `systemctl status rcai-stream` |
| "Failed to connect to AI provider" | Node can't reach the AI API. Check outbound HTTPS from your server |
| "Token not found or already used" | `STREAM_CONFIG_DIR` mismatch between `.env` and Node env, or permission issue |
| Node proxy crashes on the first chat message | `STREAM_CONFIG_DIR` is not set in the Node environment |
| Image uploads fail | `Uploads/` directory is missing or not writable by the web server user |
| Streaming works locally but not via domain | Apache proxy not configured, or `mod_proxy` not enabled |
| Password reset emails not sending | Check SMTP credentials in `.env` |
