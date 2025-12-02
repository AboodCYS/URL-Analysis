# URL Scanner

#### Description:

---

# URL Scanner (Flask + VirusTotal)

This project is a simple web application built with **Python, Flask, and SQLite** that lets a user submit any URL and receive an analysis summary on three levels: **malicious**, **harmless**, and **suspicious**. Each user has an account; passwords are securely hashed; every scan is stored in a local database and displayed in a personal dashboard.

The goal is to demonstrate a clean, minimal end-to-end security workflow: **authenticate → submit URL → call VirusTotal → store result → visualize history**. The codebase is intentionally compact so it’s easy to read and extend for a CS50 final project.

---

## Project Structure

```
URLScanner/
├── app.py                # Flask app: routes, DB helpers, VirusTotal integration
├── requirements.txt      # Python dependencies
├── .env                  # Your VirusTotal API key (not committed)
├── url_database.db       # SQLite DB (auto-created on first run)
├── templates/
│   ├── layout.html       # Base template
│   ├── index.html        # Home + scan form + latest result
│   ├── login.html        # Login form
│   ├── register.html     # Registration form
│   ├── change_password.html  # Password change form
│   └── dashboard.html    # Scan history (malicious/harmless/suspicious)
└── static/
    └── styles.css        # (optional) styles; basic UI works without it
```

### What each file does

* **app.py**

  * Initializes Flask, sessions, and the SQLite database.
  * Defines `execute_query()` to run SQL safely.
  * Creates two tables if they don’t exist:

    * `users(id, username UNIQUE, password HASH)`
    * `url(id, url, user_id, timestamp, scan_results JSON)`
  * Handles routes:

    * `/` (home), `/register`, `/login`, `/logout`, `/change_password`
    * `/scan` (POST) to run a URL scan via VirusTotal
    * `/dashboard` to view your past scans
  * Implements `virus_total_scan(target_url)` to call the VirusTotal API.

* **templates/**

  * **layout.html**: base template (header/blocks).
  * **index.html**: welcome, scan input, and a short summary of the latest scan.
  * **dashboard.html**: shows your scan history with three key counts.
  * **login.html**, **register.html**, **change\_password.html**: auth flows.

* **url\_database.db**

  * SQLite database generated automatically by `app.py` at startup.

* **.env**

  * Holds your API key. Keep this **out of version control**.

---

## Setup & Installation

1. **Clone & enter** the project folder.

2. **Create a virtual environment (optional but recommended)**

   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Add your VirusTotal API key**
   Create a `.env` file in the project root:

   ```ini
   VIRUSTOTAL_API_KEY=your_real_api_key_here
   ```

   Your key is loaded via `python-dotenv` in `app.py`.

5. **Run the server**

   ```bash
   python app.py
   ```

   Navigate to `http://127.0.0.1:5000/`.

---

## Using the App

1. **Register** a new account (username + password + confirmation).
2. **Log in.**
3. On the **Homepage**, paste a URL and click **Scan**.

   * The page shows a brief summary of the result.
4. Visit the **Dashboard** to see a table of all your scans.

   * Each row shows: ID, URL, timestamp, and counts of **malicious/harmless/suspicious**.
   * The **ID** is an auto-incrementing integer for each scan (it may appear non-contiguous if rows are ever deleted; that’s normal and not a bug for users).

You can also **change your password** anytime from the dedicated page.

---

## How Scanning Works

* The app posts the submitted URL to **VirusTotal** using the `/api/v3/urls` endpoint, then requests the analysis via `/api/v3/analyses/{id}`.
* The full API response (JSON) is stored in the `url.scan_results` column for auditing/history.
* For display, the app extracts the three key counts from the JSON:

  ```
  data.attributes.stats.malicious
  data.attributes.stats.harmless
  data.attributes.stats.suspicious
  ```
* Note: sometimes VirusTotal needs a few seconds to complete analysis. If you immediately fetch results, you may briefly get `"status": "queued"` or `"in-progress"`. A simple polling loop (retry for a few seconds until `"status": "completed"`) can make the UI more consistent. The code is structured so adding this is straightforward.

---

## Design Choices & Rationale

* **Simplicity first.** A single `app.py` keeps routing, DB access, and API integration in one place so it’s easy to learn from and modify.
* **SQLite** for zero-config persistence. It auto-creates on first run and is perfect for a small course project.
* **Password hashing** via Werkzeug’s `generate_password_hash`/`check_password_hash` for safe credential storage.
* **Sessions** stored on the filesystem, keeping the app stateless across requests without needing Redis or other infra.
* **Store raw JSON** from VirusTotal so you can extend the UI later (e.g., per-engine verdicts) without changing the database.

---

## Security & Limitations

* **For demo only**: No CSRF tokens, rate limiting, or input sanitization beyond minimal checks. In production, add CSRF protection, request validation, and HTTPS.
* The **API key** must not be committed. `.env` is used to keep secrets local.
* **Session management** uses Flask-Session filesystem storage by default; consider secure cookies and HTTPS in deployment.
* VirusTotal has **rate limits**; frequent scans may hit quotas. The app is designed to degrade gracefully.

---

## Testing Links (for your demo)

Try scanning a mix to show different outcomes:

* Harmless: `https://www.wikipedia.org/`
* Suspicious (training site): `http://testphp.vulnweb.com/`
* Malicious (EICAR test file): `https://www.eicar.org/download/eicar.com`
  *(EICAR is a safe, standard antivirus test string.)*

---

## Future Work

* Poll VirusTotal until results are `"completed"` for a smoother UX.
* Add per-engine verdicts and vendor breakdowns in the dashboard.
* Filter/search/sort scans; paginate history.
* Optional integrations (e.g., Shodan) and richer risk scoring.
* Replace inline styles with a proper design system and responsive layout.
* Add CSRF protection and stronger validation.

---

## Tech Stack

* **Python**, **Flask** (micro-framework)
* **SQLite** (persistence)
* **Werkzeug** (password hashing)
* **Requests** (HTTP client)
* **python-dotenv** (secret management)
* **HTML/CSS** (templates)

---
