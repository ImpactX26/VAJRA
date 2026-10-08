VAJRA Secure convert - demo files
=================================
Open http://127.0.0.1:8001/#/convert and upload these files.
Every "unsafe" file is harmless: it only carries a "VAJRA TEST" marker
in a place a clean file never has anything.

IMAGE TO PDF  (folder image-to-pdf, tab "Image to PDF")
  1_safe_receipt.jpg                    -> Delivered
  2_safe_but_has_camera_metadata.jpg    -> Delivered; camera and description metadata removed first
  3_unsafe_hidden_data_after_image.png  -> Burned at "Image check" (data hidden after the image)
  4_unsafe_not_really_an_image.png      -> Burned at "Image check" (not a real image)

MERGE PDFS  (folder merge-pdfs, tab "Merge PDFs"; pick 2 or more)
  1_safe_invoice.pdf + 2_safe_delivery_note.pdf          -> Delivered as merged.pdf
  1_safe_invoice.pdf + 3_unsafe_contains_script.pdf      -> Burned at "PDF check" (embedded script)
  1_safe_invoice.pdf + 4_unsafe_invisible_text.pdf       -> Burned at "PDF check" (invisible text)
  1_safe_invoice.pdf + 5_unsafe_hidden_attachment.pdf    -> Burned at "PDF check" (hidden attached file)
  1_safe_invoice.pdf + 6_unsafe_data_after_end.pdf       -> Burned at "PDF check" (data after end of file)
  Unsafe inputs are burned BEFORE anything is sent to iLovePDF.

BURNING THE TOOL'S OUTPUT  (any safe files above)
  Open "Demonstration: tamper with the returned file" and pick a change.
  iLovePDF's real result is altered in transit, and VAJRA's sandbox scan burns it.
