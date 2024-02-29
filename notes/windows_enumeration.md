# Windows Enumeration

### Rough Draft

#### schtasks

Allows you to see the scheduled tasks on your local box (once you have a shell/ssh session). The following is command useful as it will essentially answer the quesion, if we can exploit this, what kind of priviledges will we gain:

```bash
schtasks /query
...
schtasks /query /fo LIST /v /TN "FTP Backup"
```
