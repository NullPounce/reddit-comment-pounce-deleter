
# Reddit Comment Wiper (PyQt5 + PRAW)

A desktop tool to **bulk-clean your Reddit comment history**. It can optionally **back up** each comment to JSONL, then **edit each one to a single period (`.`)**, and finally **delete** it.  
Works with **Google/SSO accounts** via **browser OAuth + refresh token** (no password required).

> **Scope:** This app only operates on **your own Reddit account** and only on **comments** (not submissions). Use responsibly and in accordance with Reddit’s rules and applicable laws.

---

## ✨ Features

- **SSO-friendly** login via browser OAuth → refresh token (no Reddit password needed).
- Optional **backup** to `JSONL` before any changes.
- For each comment: **edit to “.”** → **delete** (deletes regardless of edit success).
- Handles rate-limiting politely with a small, adjustable delay.
- **Dry run** mode for counting/backup without editing or deleting.

---

## 🧰 Requirements

- **Python 3.8+**
- Install dependencies:
  ```bash
  python -m pip install -r requirements.txt
  # or
  pip install praw PyQt5
  ```

---

## 🔑 Create a Reddit App (one-time)

1. Go to **Reddit → Preferences → Apps**: <https://www.reddit.com/prefs/apps>  
2. Click **Create another app…**
3. Choose **Installed app** *(recommended for Google/SSO users)*  
   - **Name:** anything (e.g., `CommentWiper`)  
   - **Redirect URI:** `http://127.0.0.1:65010` *(must match exactly)*  
   - Save and copy the **client_id** (installed apps don’t need a secret).

   **Alternative:** choose **Web app**  
   - Same **Redirect URI**: `http://127.0.0.1:65010`  
   - You will also get a **client_secret** (enter it in the GUI if you use this type).

**Scopes required:** `identity`, `edit`, `history`, `read` (the app requests these for you).

> ⚠️ If Windows prompts about allowing a local connection, allow it (the app briefly runs a local listener to capture the OAuth redirect).

---

## ▶️ Run the App

```bash
python reddit_wipe_gui.py
```

The PyQt window will open.

---

## 🔐 Sign In — Recommended (Browser OAuth, SSO-Friendly)

This flow is best for accounts created with **Google/SSO**.

1. Enter your **Client ID** (and **Client Secret** only if you created a *Web app*).  
2. Ensure **Redirect URI** in the GUI is exactly `http://127.0.0.1:65010`.  
3. Click **Get Refresh Token (Browser Login)** → a browser tab opens → **Authorize**.  
4. After authorization, the app captures the code and fills **Refresh Token**.  
5. Click **Test Login** (optional) to verify.  
6. Click **Start Edit → Delete**.

The app will: **(optional) backup → edit to “.” → delete** each comment.

---

## 🔑 Optional Fallback — Username/Password Mode

> Only use this if your account has a **Reddit password**. Google-only accounts typically do **not** have one and will get `invalid_grant` here.

1. Fill **Client ID**, **Client Secret**, **Username**, **Password**, and **2FA code** (if enabled).  
2. Click **Test Login** (optional).  
3. Click **Start Edit → Delete**.

---

## ⚙️ Options in the GUI

- **Backup original comments**: Save a `JSONL` line per comment before changes.  
- **Backup file**: Choose where to save the backup (default filename is timestamped).  
- **Delay between actions (seconds)**: Adds a tiny gap between API calls to be polite.  
- **Dry run**: Only backs up and counts — **no edits or deletions** performed.  
- **Cancel**: Requests a graceful stop; the current item finishes, then the run stops.

---

## 🧪 What the App Actually Does

For each of your comments (newest-first):

1. **Backup** original text (if enabled).  
2. **Edit to a single period (`.`)** (some archived comments cannot be edited — that’s okay).  
3. **Delete** the comment (attempted even if the edit failed).

> Reddit can **archive** older comments; those may not accept edits, but deletion is still attempted.

---

## 🛠 Troubleshooting

**`invalid_grant`**
- You’re likely using **Google/SSO** with password mode. Use **Get Refresh Token (Browser Login)** instead.  
- Confirm **Client ID** matches your Reddit app.  
- Confirm **Redirect URI** is exactly `http://127.0.0.1:65010` in both **Reddit app settings** and the **GUI**.  
- If using password mode: it must be your **Reddit username** (not your email), and the 2FA code must be current.

**Auth succeeds but no comments are found**
- Make sure you’re logged into the intended account.  
- The API fetches the current user’s comments; if the account is new/empty, total can be zero.

**`insufficient_scope` / auth errors**
- Re-run **Get Refresh Token (Browser Login)** to grant the correct scopes.  
- Ensure your Reddit app type/redirect URI aligns with the GUI settings.

**Firewall prompts**
- Allow local connections on `127.0.0.1:65010` so the app can receive the OAuth redirect.

**Rate limits**
- Increase the **delay** if you experience throttling.

---

## 🔒 Privacy & Safety

- Credentials are used only to obtain a session for **your** account.  
- The refresh token is displayed only in your GUI and not transmitted anywhere else by this app.  
- The backup file (if enabled) is saved **locally** on your machine.

---

## ❓ FAQ

**Does it remove submissions (posts)?**  
No — only **comments**. If you want post removal, ask and we can extend the tool.

**Can it skip certain subreddits or dates?**  
Not by default, but it’s easy to add filters. Tell me what you want (e.g., “only before 2022-01-01”).

**Will it undelete?**  
No. Deletions on Reddit are permanent via the API.

---

## 🧹 Uninstall / Cleanup

- Delete the app folder and any backups you created.  
- If desired, revoke the app in **Reddit → Preferences → Apps**.

---

## ⚠️ Disclaimer

Use at your own risk. This tool changes and deletes content on your Reddit account at your request. Ensure you have adequate backups and that you comply with Reddit’s rules and relevant laws.

---

## 📝 Quick Start (TL;DR)

1. Create **Installed app** with redirect `http://127.0.0.1:65010` → copy **client_id**.  
2. Install: `pip install praw PyQt5` (or use `requirements.txt`).  
3. Run: `python reddit_wipe_gui.py`.  
4. Click **Get Refresh Token (Browser Login)** → **Authorize** → **Start Edit → Delete**.
