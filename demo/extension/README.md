# VAJRA Guard (browser extension)

Checks PDFs and images in VAJRA's sandbox in both directions, on any website:

- **Upload Guard:** files you pick or drag onto a website (for example ilovepdf.com) are checked
  before the website receives them. Unsafe files are burned and never uploaded; a red notice appears on the page.
- **Download Guard:** files you download are checked before they reach your disk. Safe files are saved
  (images rebuilt without hidden metadata); unsafe files are burned and never saved.

The extension is a front end: the checking happens in the VAJRA server running on this computer
(`http://127.0.0.1:8001`). If the server is not running, guarded downloads are **blocked**, not let through.

## Install (about 30 seconds)

1. Start VAJRA (`Start-VAJRA.cmd` on the Desktop, or `python -m demo.backend --port 8001` with `PYTHONPATH=src`).
2. Open `chrome://extensions` (or `edge://extensions` in Microsoft Edge).
3. Turn on **Developer mode** (top right in Chrome, left sidebar in Edge).
4. Click **Load unpacked** and choose this folder: `demo/extension`.
5. Pin the VAJRA shield to the toolbar (puzzle-piece icon, then the pin).

## Demo on the real iLovePDF website

1. Open https://www.ilovepdf.com/merge_pdf
2. Select `1_safe_invoice.pdf`, `2_safe_delivery_note.pdf` and `3_unsafe_contains_script.pdf` from `demo/convert_samples/merge-pdfs`.
3. VAJRA burns the script PDF before upload (red notice, top right). iLovePDF only receives the two safe files.
4. Click **Merge PDF**. The merged result is checked on download and saved as safe.

The same works on https://www.ilovepdf.com/jpg_to_pdf with the files in `demo/convert_samples/image-to-pdf`.

## Demo with the local download page

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
- Files a page generates itself (`blob:` downloads) are read back from that page; if the page has already discarded the file, the download is blocked.
- If Chrome shows "This site is trying to download multiple files", allow it (or open each file in its own tab).
- Only PDFs and images are checked; other file types download normally.
