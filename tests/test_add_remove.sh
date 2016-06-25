#!/bin/bash

echo
echo
echo "_____START_TEST_ADD_REMOVE_____"
./mypass -f./testing -no < ./new_user1 >> /dev/null
for num in {1..100}; do
  ./mypass -f./testing -aalias$num -ppassword >> /dev/null
  if [[ $? -ne 0 ]]; then
    echo "test_add_remove"
    echo "*****************FAIL**************"
    echo "adding alias$num"
    exit 1
  fi
done
for num in {1..100}; do
  ./mypass -f./testing -ralias$num -ppassword 
  if [[ $? -ne 0 ]]; then
    echo "test_add_remove"
    echo "*****************FAIL**************"
    echo "removing alias$num"
    exit 1
  fi
done

./mypass -l -f./testing -ppassword
echo "*********************PASSES**************"
echo "_____END_TEST_ADD_REMOVE_____"
exit 0


