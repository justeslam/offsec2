for i in $(seq 330 695); do date --date="$i day ago" +%Y-%m-%d-upload.pdf; done > datefile
