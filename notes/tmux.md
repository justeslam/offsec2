## Tmux Tips & Tricks

Create a new session: tmux new -s {session name}
List the tmux sessions: tmux ls
Attach (go into) a tmux session: tmux attach -t {session name}
Detach: Prefix + d
Prefix key: Ctrl + b
Search through your past commands: Ctrl + r
For a new shell: Prefix + c
Switch to that shell: Prefix + 0 (or 1,2,3,..)
tmux kill-session - t
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
Copy: Prefix + [ -> space + direction
Paste: Prefix + ]

set -g mouse on