## Tmux Tips & Tricks

Create a new session: tmux new -s {session name}
List the tmux sessions: tmux ls
Attach (go into) a tmux session: tmux attach -t {session name}
Detach: Prefix + d
Prefix key: Ctrl + b
Search through your past commands: Ctrl + r
For a new shell: Prefix + c
Switch to that shell: Prefix + 0 (or 1,2,3,..)
tmux kill-session -t
Split window vertically: prefix + %
Split window horizontally: prefix + “
Switch panes interactively: Prefix + arrow keys
Display pane numbers: Prefix + q
Switch pane: Prefix + q + number
Adjust pane size: Prefix + Ctrl + arrow keys
Pre-made pane layout: Prefix + Alt + 4
Make a new window: Prefix + c
Rename window: Prefix + ,
Overview of session: Prefix + w 
Copy: Prefix + [ -> space + direction + Enter
Paste: Prefix + ] (You may need to ":set paste" in vi)
Search down: Prefix + [ + /
Search up: Prefix + [ + ?
Kill pane: Ctrl-B + X

#### Tmux Logging

Toggle (start/stop) logging in the current pane: prefix + shift + p
Save visible text, in the current pane. Equivalent of a "textual screenshot": prefix + alt + p
Save complete pane history to a file. Convenient if you retroactively remember you need to log/save all the work: prefix + alt + shift + p
Clear pane history: prefix + alt + c
Fetch and source plugin: prefix + I

set -g mouse on

## Vi Tricks

Get rid of spaces: "%s/ //g"
Substitute "|" with newline: "%s/|/\r/g"

## Slicing and Dicing Output

Cat the 1st and 3rd field separated by ':':

```bash
cat creds.txt| cut -d ":" -f 1,3
```
