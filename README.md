My fork of xcwd - cleaned up code and did some improvements. Only works in
Linux.

xcwd - X current working directory
==================================
xcwd is a simple tool that prints the current working directory of the
currently focused window.

The main goal is to launch applications directly into the same directory as the
focused applications. This is especially useful to open a new terminal or a
file explorer.

Disclaimer
----------
This program is basically a hack, but it works well with my setup and I hope
it will work for you as well :)

This script **can't** retrieve the working directory of a "single instance
application" nor terminal multiplexer, e.g.:
  - tmux, screen
  - lilyterm
  - konsole
  - urxvtc with urxvtd
  - programs with tabs

The application works with the following terminals:
  - urxvt
  - xterm
  - gnome terminal
  - terminology

How it works
------------
  - Get the handle of the focused window.
  - Try to get the PID of the process using the window's `_NET_WM_PID`
    attributes.
  - Find the deepest child process.
  - Print the working directory of this process to stdout.

If one of these steps fail, xcwd prints the content of the `$HOME` variable.

Requirements
------------
  - Linux
  - libX11

Installation
------------
* Clone this repository
* `make`
* `sudo make install`

Usage
-----
* `xcwd [-h|--help]`
* `xcwd [-a|--all|-t|--tty-only]`

Examples:
* `urxvt -cd "$(xcwd)"`
* `xterm -e 'cd "$(xcwd)" && "$(SHELL)"'`
* `gnome-terminal --working-directory="$(xcwd)"`
* `pcmanfm "$(xcwd)"`
