
#!/usr/bin/env python3
"""
Reddit Comment Wiper (PyQt5 + PRAW) — supports Google/SSO via Browser OAuth
----------------------------------------------------------------------------
- Replace each of your comments with "." then delete it.
- Optional JSON backup of all comments before modification.
- Two auth modes:
  1) Browser OAuth (recommended, works with Google/SSO accounts). Gets a refresh token.
  2) Username/Password (script app) for accounts with a Reddit password/2FA.

Dependencies:
  pip install praw PyQt5

Quick start (Browser OAuth, SSO-friendly):
1) Create a Reddit app: https://www.reddit.com/prefs/apps
   - Choose type: "installed app" (or "web app" if you prefer and have a secret)
   - Redirect URI (must exactly match): http://127.0.0.1:65010
   - Note your client_id (and secret if "web app"; for "installed app" no secret is required).

2) Run this program and click "Get Refresh Token (Browser Login)".
   - It will open your browser for Reddit authorization.
   - After you allow, you'll see "Authorized. You can close this tab."
   - The app will display and store your refresh token in the field.

3) Click "Start Edit → Delete".

Username/Password mode:
- Works only if your account has a Reddit password (Google-SSO accounts usually don't).
- If you have 2FA enabled, enter the 6-digit code; the tool appends it automatically.

Scopes used: identity, edit, history, read
"""

import sys
import os
import time
import json
import random
import traceback
import secrets
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLineEdit, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QGridLayout, QTextEdit, QCheckBox, QProgressBar, QFileDialog, QMessageBox, QSpinBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtGui import QDesktopServices

try:
    import praw
    from prawcore.exceptions import PrawcoreException, OAuthException, ResponseException, Forbidden, NotFound, RequestException, BadRequest
except Exception as e:
    print("Missing dependencies. Please install with: pip install praw PyQt5")
    raise

APP_TITLE = "Reddit Comment Wiper (OAuth-ready)"
DEFAULT_USER_AGENT = "RedditCommentWiper/2.0 (PyQt5 + PRAW)"
OAUTH_PORT = 65010
DEFAULT_REDIRECT_URI = f"http://127.0.0.1:{OAUTH_PORT}"
BACKUP_FILENAME = lambda: f"reddit_comments_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
OAUTH_SCOPES = {"identity", "edit", "history", "read"}

# --------------------------- OAuth helper server ---------------------------

class OAuthResult:
    def __init__(self):
        self.code = None
        self.state = None
        self.error = None

class OAuthHandler(BaseHTTPRequestHandler):
    # Shared among instances; set before server starts
    expected_state = None
    result_obj = None

    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            state = qs.get("state", [None])[0]
            code = qs.get("code", [None])[0]
            error = qs.get("error", [None])[0]

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            if error:
                OAuthHandler.result_obj.error = error
                self.wfile.write(b"<h1>Authorization failed</h1><p>You can close this tab.</p>")
                return

            if not code or not state:
                self.wfile.write(b"<h1>Missing code/state</h1><p>You can close this tab.</p>")
                return

            if state != OAuthHandler.expected_state:
                self.wfile.write(b"<h1>State mismatch</h1><p>You can close this tab.</p>")
                return

            OAuthHandler.result_obj.code = code
            OAuthHandler.result_obj.state = state
            self.wfile.write(b"<h1>Authorized</h1><p>You can close this tab.</p>")
        except Exception:
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence the HTTP server logs into stdout
        pass

def run_oauth_server(expected_state, result_obj, stop_after_seconds=180):
    OAuthHandler.expected_state = expected_state
    OAuthHandler.result_obj = result_obj
    server = HTTPServer(("127.0.0.1", OAUTH_PORT), OAuthHandler)
    server.timeout = 0.5

    start = time.time()
    try:
        while time.time() - start < stop_after_seconds and not result_obj.code and not result_obj.error:
            server.handle_request()
    finally:
        try:
            server.server_close()
        except Exception:
            pass

# ------------------------------- Worker -----------------------------------

class WipeWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)  # current, total
    done = pyqtSignal(int, int, int)  # edited, deleted, failed
    fatal = pyqtSignal(str)

    def __init__(self, auth_mode: str, creds: dict, opts: dict, parent=None):
        super().__init__(parent)
        self.auth_mode = auth_mode  # "refresh", "password"
        self.creds = creds
        self.opts = opts
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def _sleep_with_cancel(self, seconds: float):
        end = time.time() + seconds
        while time.time() < end:
            if self._cancel:
                return
            time.sleep(min(0.2, end - time.time()))

    def _make_reddit(self):
        user_agent = self.creds.get("user_agent") or f"{DEFAULT_USER_AGENT} by u/{self.creds.get('username','')}"
        if self.auth_mode == "refresh":
            return praw.Reddit(
                client_id=self.creds["client_id"].strip(),
                client_secret=(self.creds.get("client_secret") or None),
                refresh_token=self.creds["refresh_token"].strip(),
                user_agent=user_agent,
                redirect_uri=self.creds.get("redirect_uri") or DEFAULT_REDIRECT_URI,
                ratelimit_seconds=300,
            )
        elif self.auth_mode == "password":
            password = self.creds.get("password", "")
            otp = self.creds.get("otp", "").strip()
            if otp:
                password = f"{password}:{otp}"
            return praw.Reddit(
                client_id=self.creds["client_id"].strip(),
                client_secret=self.creds["client_secret"].strip(),
                username=self.creds["username"].strip(),
                password=password,
                user_agent=user_agent,
                ratelimit_seconds=300,
            )
        else:
            raise RuntimeError(f"Unknown auth mode: {self.auth_mode}")

    def run(self):
        edited = 0
        deleted = 0
        failed = 0

        try:
            reddit = self._make_reddit()
            me = reddit.user.me()
            if not me:
                raise RuntimeError("Authentication failed (user.me() returned None).")
            self.log.emit(f"Authenticated as u/{me}.")

            # Backup setup
            backup_fp = None
            if self.opts.get("backup_enabled"):
                backup_path = self.opts.get("backup_path") or os.path.join(os.getcwd(), BACKUP_FILENAME())
                os.makedirs(os.path.dirname(os.path.abspath(backup_path)), exist_ok=True)
                backup_fp = open(backup_path, "w", encoding="utf-8")
                self.log.emit(f"Backing up original comments to: {backup_path}")

            # Fetch comments
            redditor = reddit.redditor(str(me))
            self.log.emit("Fetching your comments (can take a while)...")

            comments = []
            try:
                for c in redditor.comments.new(limit=None):
                    comments.append(c)
            except Exception as e:
                self.log.emit(f"Error while listing comments: {e}")
                raise

            total = len(comments)
            self.log.emit(f"Found {total} comments to process.")
            if total == 0:
                self.done.emit(0, 0, 0)
                if backup_fp: backup_fp.close()
                return

            # Dry-run?
            if self.opts.get("dry_run"):
                if backup_fp:
                    for idx, c in enumerate(comments, start=1):
                        if self._cancel: break
                        try:
                            obj = {
                                "id": c.id,
                                "subreddit": str(c.subreddit) if getattr(c, "subreddit", None) else None,
                                "created_utc": getattr(c, "created_utc", None),
                                "permalink": f"https://www.reddit.com{c.permalink}" if getattr(c, "permalink", None) else None,
                                "body": c.body,
                            }
                            backup_fp.write(json.dumps(obj, ensure_ascii=False) + "\\n")
                        except Exception as ex:
                            self.log.emit(f"[Backup] Failed for {getattr(c,'id','?')}: {ex}")
                        self.progress.emit(idx, total)
                self.log.emit("Dry run complete (no edits or deletions performed).")
                if backup_fp: backup_fp.close()
                self.done.emit(0, 0, 0)
                return

            delay_sec = float(self.opts.get("delay_sec", 2.0))

            for idx, c in enumerate(comments, start=1):
                if self._cancel:
                    break

                cid = getattr(c, "id", "?")
                try:
                    # Backup original
                    if backup_fp:
                        try:
                            obj = {
                                "id": c.id,
                                "subreddit": str(c.subreddit) if getattr(c, "subreddit", None) else None,
                                "created_utc": getattr(c, "created_utc", None),
                                "permalink": f"https://www.reddit.com{c.permalink}" if getattr(c, "permalink", None) else None,
                                "body": c.body,
                            }
                            backup_fp.write(json.dumps(obj, ensure_ascii=False) + "\\n")
                        except Exception as ex:
                            self.log.emit(f"[Backup] Failed for {cid}: {ex}")

                    # Edit to "."
                    try:
                        c.edit(".")
                        edited += 1
                        self.log.emit(f"[{idx}/{total}] Edited comment {cid}")
                    except Exception as ex_edit:
                        self.log.emit(f"[{idx}/{total}] Edit failed for {cid}: {ex_edit} (will still try to delete)")

                    self._sleep_with_cancel(delay_sec + random.uniform(0, 0.5))
                    if self._cancel: break

                    # Delete
                    try:
                        c.delete()
                        deleted += 1
                        self.log.emit(f"[{idx}/{total}] Deleted comment {cid}")
                    except Exception as ex_del:
                        failed += 1
                        self.log.emit(f"[{idx}/{total}] Delete failed for {cid}: {ex_del}")

                    self._sleep_with_cancel(delay_sec + random.uniform(0, 0.5))

                except (PrawcoreException, OAuthException, ResponseException, RequestException, BadRequest) as api_ex:
                    failed += 1
                    self.log.emit(f"[{idx}/{total}] API error for {cid}: {api_ex}")
                    self._sleep_with_cancel(delay_sec + random.uniform(0, 0.5))
                except Exception as ex:
                    failed += 1
                    self.log.emit(f"[{idx}/{total}] Unexpected error for {cid}: {ex}\\n{traceback.format_exc()}")
                    self._sleep_with_cancel(delay_sec + random.uniform(0, 0.5))

                self.progress.emit(idx, total)

            if backup_fp: backup_fp.close()
            self.done.emit(edited, deleted, failed)

        except Exception as fatal_ex:
            self.fatal.emit(f"Fatal error: {fatal_ex}\\n{traceback.format_exc()}")

# ------------------------------- UI ---------------------------------------

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.oauth_refresh_token = ""
        self._build_ui()

    def _build_ui(self):
        grid = QGridLayout()
        row = 0

        # App credentials
        grid.addWidget(QLabel("Client ID"), row, 0)
        self.client_id = QLineEdit()
        self.client_id.setPlaceholderText("Your Reddit app client_id (personal use script / installed app)")
        grid.addWidget(self.client_id, row, 1); row += 1

        grid.addWidget(QLabel("Client Secret (optional for installed app)"), row, 0)
        self.client_secret = QLineEdit()
        self.client_secret.setEchoMode(QLineEdit.Password)
        self.client_secret.setPlaceholderText("Leave blank for 'installed app'")
        grid.addWidget(self.client_secret, row, 1); row += 1

        grid.addWidget(QLabel("Redirect URI"), row, 0)
        self.redirect_uri = QLineEdit(DEFAULT_REDIRECT_URI)
        grid.addWidget(self.redirect_uri, row, 1); row += 1

        grid.addWidget(QLabel("User Agent"), row, 0)
        self.user_agent = QLineEdit()
        self.user_agent.setPlaceholderText(DEFAULT_USER_AGENT)
        grid.addWidget(self.user_agent, row, 1); row += 1

        # OAuth (refresh token) section
        grid.addWidget(QLabel("Refresh Token (preferred)"), row, 0)
        self.refresh_token = QLineEdit()
        self.refresh_token.setPlaceholderText("Use 'Get Refresh Token (Browser Login)' if empty")
        grid.addWidget(self.refresh_token, row, 1); row += 1

        oauth_row = QHBoxLayout()
        self.get_token_btn = QPushButton("Get Refresh Token (Browser Login)")
        self.get_token_btn.clicked.connect(self._do_browser_oauth)
        oauth_row.addWidget(self.get_token_btn)
        grid.addLayout(oauth_row, row, 0, 1, 2); row += 1

        # Username/Password fallback
        grid.addWidget(QLabel("Username (fallback mode)"), row, 0)
        self.username = QLineEdit()
        self.username.setPlaceholderText("Only if your account has a Reddit password")
        grid.addWidget(self.username, row, 1); row += 1

        grid.addWidget(QLabel("Password"), row, 0)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        grid.addWidget(self.password, row, 1); row += 1

        grid.addWidget(QLabel("2FA code (if enabled)"), row, 0)
        self.otp = QLineEdit()
        self.otp.setPlaceholderText("e.g., 123456 (optional)")
        grid.addWidget(self.otp, row, 1); row += 1

        # Options
        self.backup_box = QCheckBox("Backup original comments to JSONL before changes (recommended)")
        self.backup_box.setChecked(True)
        grid.addWidget(self.backup_box, row, 0, 1, 2); row += 1

        self.backup_path_label = QLabel("Backup file")
        grid.addWidget(self.backup_path_label, row, 0)
        path_row = QHBoxLayout()
        self.backup_path = QLineEdit(BACKUP_FILENAME())
        self.pick_backup = QPushButton("Browse…")
        self.pick_backup.clicked.connect(self._choose_backup_path)
        path_row.addWidget(self.backup_path)
        path_row.addWidget(self.pick_backup)
        grid.addLayout(path_row, row, 1); row += 1

        # Delay
        delay_row = QHBoxLayout()
        delay_row.addWidget(QLabel("Delay between actions (seconds):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10)
        self.delay_spin.setValue(2)
        delay_row.addWidget(self.delay_spin)
        delay_row.addStretch(1)
        grid.addLayout(delay_row, row, 0, 1, 2); row += 1

        # Dry run
        self.dry_run = QCheckBox("Dry run (only backup + count; no edits/deletes)")
        self.dry_run.setChecked(False)
        grid.addWidget(self.dry_run, row, 0, 1, 2); row += 1

        # Buttons
        btn_row = QHBoxLayout()
        self.test_btn = QPushButton("Test Login")
        self.start_btn = QPushButton("Start Edit → Delete")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)

        self.test_btn.clicked.connect(self._test_login)
        self.start_btn.clicked.connect(self._start)
        self.cancel_btn.clicked.connect(self._cancel)

        btn_row.addWidget(self.test_btn)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.cancel_btn)
        grid.addLayout(btn_row, row, 0, 1, 2); row += 1

        # Progress + Log
        self.progress = QProgressBar()
        self.progress.setValue(0)
        grid.addWidget(self.progress, row, 0, 1, 2); row += 1

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        grid.addWidget(self.log, row, 0, 1, 2); row += 1

        self.setLayout(grid)
        self.resize(760, 680)

    # ------------------------- UI helpers -------------------------

    def _choose_backup_path(self):
        path, _ = QFileDialog.getSaveFileName(self, "Choose backup file", self.backup_path.text(), "JSON Lines (*.jsonl);;All Files (*)")
        if path:
            self.backup_path.setText(path)

    def _get_common_creds(self):
        return {
            "client_id": self.client_id.text().strip(),
            "client_secret": (self.client_secret.text().strip() or None),
            "redirect_uri": self.redirect_uri.text().strip() or DEFAULT_REDIRECT_URI,
            "user_agent": self.user_agent.text().strip() or DEFAULT_USER_AGENT,
        }

    def _get_password_creds(self):
        c = self._get_common_creds()
        c.update({
            "username": self.username.text().strip(),
            "password": self.password.text(),
            "otp": self.otp.text().strip(),
        })
        return c

    def _get_refresh_creds(self):
        c = self._get_common_creds()
        c.update({"refresh_token": self.refresh_token.text().strip()})
        return c

    def _get_opts(self):
        return {
            "backup_enabled": self.backup_box.isChecked(),
            "backup_path": self.backup_path.text().strip(),
            "delay_sec": self.delay_spin.value(),
            "dry_run": self.dry_run.isChecked(),
        }

    def _toggle_busy(self, busy: bool):
        for w in (self.test_btn, self.start_btn, self.get_token_btn, self.pick_backup,
                  self.client_id, self.client_secret, self.redirect_uri, self.user_agent,
                  self.refresh_token, self.username, self.password, self.otp,
                  self.backup_box, self.backup_path, self.delay_spin, self.dry_run):
            w.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)

    # --------------------- OAuth browser flow ---------------------

    def _do_browser_oauth(self):
        creds = self._get_common_creds()
        if not creds["client_id"]:
            QMessageBox.warning(self, "Missing client_id", "Enter your Reddit app client_id first.")
            return
        # If installed app, secret should be empty/None; if you created a "web app", you can keep the secret

        redirect_uri = creds["redirect_uri"]
        if not redirect_uri.startswith("http://127.0.0.1:"):
            QMessageBox.warning(self, "Redirect URI", f"Set Redirect URI to {DEFAULT_REDIRECT_URI} in both this app AND your Reddit app config.")
            return

        try:
            reddit = praw.Reddit(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],  # None for installed app
                redirect_uri=redirect_uri,
                user_agent=creds["user_agent"],
            )

            state = secrets.token_urlsafe(24)
            auth_url = reddit.auth.url(sorted(OAUTH_SCOPES), state, "permanent")

            # Start tiny local server to catch the redirect
            result = OAuthResult()
            server_thread = Thread(target=run_oauth_server, args=(state, result), daemon=True)
            server_thread.start()

            # Open browser
            QDesktopServices.openUrl(QUrl(auth_url))
            self.log.append("Opened browser for Reddit authorization…")

            # Poll for up to 3 minutes while server is running
            start = time.time()
            while time.time() - start < 180:
                QApplication.processEvents()
                if result.error:
                    QMessageBox.critical(self, "Authorization error", f"Error: {result.error}")
                    return
                if result.code:
                    break
                time.sleep(0.2)

            if not result.code:
                QMessageBox.critical(self, "Timeout", "Did not receive authorization code. Make sure the redirect URI matches exactly.")
                return

            # Exchange code -> refresh token
            refresh_token = reddit.auth.authorize(result.code)
            if not refresh_token:
                # PRAW stores it internally, but returns None for some versions; try to read it explicitly
                refresh_token = getattr(reddit.auth, "refresh_token", None)

            if not refresh_token:
                QMessageBox.critical(self, "Failed", "Did not obtain a refresh token.")
                return

            self.refresh_token.setText(refresh_token)
            self.log.append("Obtained refresh token. You can now click Start.")
            QMessageBox.information(self, "Success", "Refresh token saved in the field.")

        except Exception as e:
            QMessageBox.critical(self, "OAuth error", f"{e}")

    # --------------------- Test + Start flow ----------------------

    def _test_login(self):
        # Prefer refresh token if provided
        if self.refresh_token.text().strip():
            creds = self._get_refresh_creds()
            try:
                reddit = praw.Reddit(
                    client_id=creds["client_id"],
                    client_secret=creds["client_secret"],
                    refresh_token=creds["refresh_token"],
                    redirect_uri=creds["redirect_uri"],
                    user_agent=creds["user_agent"],
                )
                me = reddit.user.me()
                if me:
                    QMessageBox.information(self, "Success", f"Authenticated via refresh token as u/{me}")
                else:
                    QMessageBox.critical(self, "Failed", "Authentication failed (user.me() returned None).")
            except Exception as e:
                QMessageBox.critical(self, "Failed", f"Auth error with refresh token:\n{e}")
            return

        # Fallback: username/password
        creds = self._get_password_creds()
        missing = [k for k in ("client_id", "client_secret", "username", "password") if not creds.get(k)]
        if missing:
            QMessageBox.warning(self, "Missing info", "Either provide a Refresh Token OR fill these fields: " + ", ".join(missing))
            return

        try:
            password = creds["password"]
            otp = creds.get("otp", "").strip()
            if otp:
                password = f"{password}:{otp}"

            reddit = praw.Reddit(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                username=creds["username"],
                password=password,
                user_agent=creds["user_agent"],
                ratelimit_seconds=60,
            )
            me = reddit.user.me()
            if me:
                QMessageBox.information(self, "Success", f"Authenticated via username/password as u/{me}")
            else:
                QMessageBox.critical(self, "Failed", "Authentication failed (user.me() returned None).")
        except Exception as e:
            QMessageBox.critical(self, "Failed", f"Authentication error:\n{e}\n\nCommon causes for 'invalid_grant':\n• Using Google SSO without setting a Reddit password (use the Browser Login instead)\n• Wrong username (use your Reddit username, not email)\n• Client ID/secret mismatch or spaces\n• App type not 'script' (for password mode)")

    def _start(self):
        auth_mode = None
        creds = None
        if self.refresh_token.text().strip():
            auth_mode = "refresh"
            creds = self._get_refresh_creds()
        else:
            auth_mode = "password"
            creds = self._get_password_creds()

        # Basic checks
        if auth_mode == "refresh":
            missing = [k for k in ("client_id", "refresh_token") if not creds.get(k)]
            if missing:
                QMessageBox.warning(self, "Missing info", f"Please fill: {', '.join(missing)}")
                return
        else:
            missing = [k for k in ("client_id", "client_secret", "username", "password") if not creds.get(k)]
            if missing:
                QMessageBox.warning(self, "Missing info", f"Please fill: {', '.join(missing)}")
                return

        if self.backup_box.isChecked():
            try:
                backup_dir = os.path.dirname(os.path.abspath(self.backup_path.text().strip() or BACKUP_FILENAME()))
                os.makedirs(backup_dir, exist_ok=True)
            except Exception as e:
                QMessageBox.critical(self, "Backup path error", f"Cannot create/open backup directory:\n{e}")
                return

        self.log.clear()
        self.progress.setValue(0)
        self._toggle_busy(True)

        self.worker = WipeWorker(auth_mode, creds, self._get_opts())
        self.worker.log.connect(self._append_log)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.fatal.connect(self._on_fatal)
        self.worker.start()

    def _cancel(self):
        if hasattr(self, "worker") and self.worker:
            self.worker.cancel()
            self._append_log("Cancellation requested. Finishing current item...")

    def _append_log(self, msg: str):
        self.log.append(msg)

    def _on_progress(self, current: int, total: int):
        if total > 0:
            self.progress.setMaximum(total)
            self.progress.setValue(current)

    def _on_done(self, edited: int, deleted: int, failed: int):
        self._toggle_busy(False)
        self._append_log(f"Done. Edited: {edited}, Deleted: {deleted}, Failed: {failed}")
        QMessageBox.information(self, "Complete", f"Edited: {edited}\\nDeleted: {deleted}\\nFailed: {failed}")

    def _on_fatal(self, message: str):
        self._toggle_busy(False)
        self._append_log(message)
        QMessageBox.critical(self, "Fatal error", message)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
