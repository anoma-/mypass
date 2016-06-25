#!/bin/bash
echo
echo
echo "_____START_TEST_SAME_NEW_USER_INPUT_____"
./mypass -no -f./testing < ./new_user1 >> /dev/null
user1=$(./mypass -aalias -f./testing -ppassword)
./mypass -no -f./testing < ./new_user2 >> /dev/null
user2=$(./mypass -aalias -f./testing -ppassword)
./mypass -no -f./testing < ./new_user3 >> /dev/null
user3=$(./mypass -aalias -f./testing -ppassword)
./mypass -no -f./testing < ./new_user4 >> /dev/null
user4=$(./mypass -aalias -f./testing -ppassword)

  echo "$user1" 
  echo "$user2" 
  echo "$user3" 
  echo "$user4"

if [ "$user1" == "$user2" -a "$user1" == "$user3" -a "$user1" == "$user4" ]; then
  echo "*****************Passes*******************"
  exit 0
else
  echo "test_same_new_user_input"
  echo $user1
  echo $user2
  echo $user3
  echo $user4
  echo "******************FAIL********************"
  exit 1
fi
echo "_____END_TEST_SAME_NEW_USER_INPUT_____"

