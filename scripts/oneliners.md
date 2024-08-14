## Bash One-Liners

#### Make txt file of words lowercase and remove duplicates without ordering the words

```bash
awk '!a[tolower($0)]++' input.txt > output.txt
```

#### Take the second field out output

```bash
cat file.txt | awk '{print $2}'
```

#### Make a txt file of all port numbers

```bash
seq 1 65535 > ports.txt
```

#### Tee output to file and stout

```bash
enum4linux | tee file.txt
```