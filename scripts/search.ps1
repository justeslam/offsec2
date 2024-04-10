# Capture the search word from the command line arguments
$searchWord = $args[0]

# Define paths to exclude from the search
$excludedPaths = @("C:\Windows\Assembly", "C:\Program Files", "C:\Windows\System32")

# Search for files containing the specified word, excluding the defined paths
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -File |
    Where-Object {
        $path = $_.FullName
        -not ($excludedPaths | Where-Object { $path.StartsWith($_) })
    } |
    Select-String -Pattern $searchWord |
    Select-Object -Unique Path
