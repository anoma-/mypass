#!/bin/bash
#  set sshuser to user@ip_address
#  if you register a key-combo in your DE to call this program
#  you can use it without pulling up a terminal
sshuser=
if [[ "x$sshuser" != "x" ]]; then

  alias=$(zenity --entry --title="Enter Alias" --text="Enter the alias") 
  if [[ ! -z $alias:+x ]]; then

    echo $(ssh "$sshuser" mypass -a"$alias") | xclip -selection clipboard
  fi
else
  echo "Have not set ssh user"
fi


