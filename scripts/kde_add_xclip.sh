#! /bin/bash
#  If you have xclip installed, use this script to copy the return
#  value of a call to mypass into the clipboard only on a succeful call.

alias=$(kdialog --title "Mypass" --inputbox "Enter Alias")
if [[ -z "$alias" ]]; then 
	echo "Failed to get alias"
else

	rt=$(mypass -a"$alias") && echo "$rt" | xclip -selection clipboard
	echo $rt
fi
