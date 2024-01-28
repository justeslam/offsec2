Checklist:

    Are filenames reflected back on the page? If so, are they HTML Entity encoded (XSS via file names)?

    Does it accept .zip files? Try a ZipSlip

    If it processes an image, check for Image Tragick (CVE-2016-3714)

    Can you bypass file type restrictions by changing the content-type value?

    Can you bypass file type restrictions by forging valid magic bytes?

    Can you upload a file with a less-common extension (such as .phtml)?

    Try playing with the filename in the request, a potential vector for traversal or SQL injection.

    Check for the acceptance of double extensions on uploaded files.

    Test for null-byte injection.

    Is the server windows? Try adding a trailing . to bypass extension blacklists, this dot will be removed automatically by the OS.

    Can you upload an SVG for XSS?

    If supported by the webserver, can you upload .htaccess files?

    Does the backend process the image with the PHP GD library?

    Is the app vulnerable to the infamous ffmpeg exploit?

    Can custom polyglots be developed to bypass specific filters?

    Does the app pass the file name to some sort of system function? If so, can you achieve RCE via code injection within the file name?

    Does the application run the uploaded file through exiftool? If so, can you get RCE via the djvu exploit?

    Can you bypass extension filters by using varied capitalization?

    Look for '?page=' in the source code to identify potential vectors.

Resource: https://www.onsecurity.io/blog/file-upload-checklist/, https://github.com/mikesmullin/pentest-notes
