#! /bin/bash
#  If you have xclip installed, use this script to copy the return
#  value of a call to mypass into the clipboard only on a succeful call.

rt=$(mypass "$@") && echo "$rt" | xclip -selection clipboard
echo $rt
