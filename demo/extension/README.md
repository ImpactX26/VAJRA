# VAJRA Download Guard (browser extension)

Checks every PDF and image you download in VAJRA's sandbox before it reaches your disk.
Safe files are saved (images rebuilt without hidden metadata). Unsafe files are burned and never saved.

The extension is a front end: the checking happens in the VAJRA server running on this computer
(`http://127.0.0.1:8001`). If the server is not running, guarded downloads are **blocked**, not let through.

## Install (about 30 seconds)

1. Start VAJRA (`Start-VAJRA.cmd` on the Desktop, or `python -m demo.backend --port 8001` with `PYTHONPATH=src`).
2. Open `chrome://extensions` (or `edge://extensions` in Microsoft Edge).
3. Turn on **Developer mode** (top right in Chrome, left sidebar in Edge).
4. Click **Load unpacked** and choose this folder: `demo/extension`.
5. Pin the VAJRA shield to the toolbar (puzzle-piece icon, then the pin).

## Demo

1. Open `http://127.0.0.1:8090/downloads` (or click **Test downloads** in the extension popup).
2. Click a `safe` file: a green "Safe: checked by VAJRA" notice appears and the file is saved.
3. Click an `unsafe` file: a red "Burned by VAJRA" notice explains why, and nothing is saved.
4. Open the popup: live status, counts and the recent files list. **Audit trail** opens the Monitor page.

Right-click menu:

- **Check this file with VAJRA** on any link
- **Save this image through VAJRA** on any image
- **Convert this image to PDF with VAJRA (iLovePDF)** on any image

## What it does not do

- It does not run on Chrome for Android or iOS (mobile Chrome has no extensions).
- Downloads created by a page script (`blob:` URLs) cannot be fetched again by the extension and are not checked.
- Only PDFs and images are checked; other file types download normally.
