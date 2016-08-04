#!/bin/bash

echo
echo
echo "_____START_IMPORT_PASSWORD_____"
./mypass -f./testing -no < ./new_user1 >> /dev/null
for num in {1..100}; do
  ./mypass -f./testing -aalias$num -ipassword -ppassword >> /dev/null
  if [[ $? -ne 0 ]]; then
    echo "test_import"
    echo "*****************FAIL**************"
    echo "importing alias$num"
    exit 1
  fi
done
for num in {1..100}; do
  ./mypass -f./testing -ralias$num -ppassword 
  if [[ $? -ne 0 ]]; then
    echo "test_import"
    echo "*****************FAIL**************"
    echo "removing alias$num"
    exit 1
  fi
done

echo "*********************PASSES**************"
echo "_____END_TEST_IMPORT_____"
exit 0


