#! /usr/bin/env bash

vg="/home/toa/git/valgrind/bin/valgrind --leak-check=full --show-leak-kinds=all --suppressions=../suppress"
alloc="./src/mymalloc.c"
# If the command finds memory leak, append to report
report()
{
  $command 2> valgrind_output
  grep "lost\|reachable" valgrind_output | awk '{print $4$7}' | grep -e "[1-9]+"  && 
    echo "***********Memory Leak ************" >> report                          &&
    echo "$mem_failure" >> report                                                 &&
    cat valgrind_output >> report                                                 &&
    echo "**********************************" >> report                              
}
# Change the number of when to return NULL in $alloc function
# $alloc global var, requires argument $num to set the equality to
ch_alloc()
{
  sed -i '/if/ s/i == ./''i == '${1}'/' $alloc
}

get_num_calls()
{
  ch_alloc 0 
  make memfailure 2> /dev/null 1> /dev/null
  var=$($1)
  read -d"\n" -a arr <<< $(echo $var | egrep -o "[0-9]+" | sort -r)
  return ${arr[0]}
}

test_commands[0]="./mem_fail -f./f -aalias"
test_commands[1]="./mem_fail -f./f -ralias"
test_commands[2]="./mem_fail -f./f -l"
test_commands[3]="./mem_fail -f./f -aalias2 -L64 -m12345678"
test_commands[4]="./mem_fail -f./f -galias2 -e0123456789"
test_commands[5]="./mem_fail -f./f -galias2 -e -mman"
test_commands[6]="./mem_fail -f./f -galias2 -e -m -L18"
test_commands[7]="./mem_fail -f./f -xsecret"
test_commands[8]="./mem_fail -f./f -atest -iimport"
test_commands[9]="./mem_fail -f./f -rtest"
test_commands[10]="./mem_fail -f./f -aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
test_commands[11]="./mem_fail -f./f -atest -iimporttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
test_commands[12]="./mem_fail -f./f -aa -mmandddddatorrrrrrrrrrrrrry -easdfbk;asldkfpoiwaksd;flkja;slkdjf;lkasd;flkajs;dlkfj"
test_commands[13]="./mem_fail -f./no_file -ablah"
test_commands[14]="./mem_fail -f./f -galias2 -Ltw"
test_commands[15]="./mem_fail -f./f -gnot_existing"
test_commands[16]="./mem_fail -f./f -gnotexistant -mmandayantorye'asdf -e198395r0"
test_commands[17]="./mem_fail -f./f -gnotexistant -mmand -e19"
test_commands[18]="./mem_fail asdfasdlfkja;slkdjf;alksjdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

start_tests()
{
  cnt=${#test_commands[@]}
  let i=0
  while [[ $i -lt $cnt ]]; do
    get_num_calls "${test_commands[$i]}"
    num=${arr[0]}
    iter=0
    while [[ $iter -le $num ]]; do
      let iter++
      ch_alloc $iter
      make memfailure
      command="$vg ${test_commands[$i]}"
      report 
    done
    let i++
  done
}

start_tests
