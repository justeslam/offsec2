## Client-Side Attacks

When choosing an attack vector and payload, we must first perform reconnaissance to determine the operating system of the target as well as any installed applications. 

This is a critical first step, as our payload must match the capability of the target. 

	For example, if the target is running the Windows operating system, we can use a variety of client-side attacks like malicious JScript code executed through the Windows Script Host or .lnk shortcut files pointing to malicious resources. If the target has installed Microsoft Office, we could leverage documents with embedded malicious macros.

One approach is to inspect the **metadata tags** of publicly-available documents associated with the target organization. Bear in mind that our findings may be outdated if we are inspecting older documents. In addition, different branches of the organization may use slightly different software.

If we want to interact with the target's web site, we could also use tools like gobuster3 with the -x parameter to search for specific file extensions on the target's web site. This is noisy and will generate log entries on the target. 


### Exif Tool

To display the metadata of any supported file.
- Website: https://exiftool.org/ 

