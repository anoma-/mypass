#!/bin/bash
echo
echo
echo "_____START_TEST_KNOWN_GENERATION_____"
./mypass -no -f./testing < ./new_user1 >> /dev/null
output=$(./mypass -aalias -f./testing -ppassword)
if [[ $output == "{B_*3a}s9nyu{q<-:>" ]]; then
  echo "****************PASSES****************"
  echo "_____END_TEST_KNOWN_GENERATION_____"
  exit 0
else
  echo "test_known_generation"
  echo "****************FAIL*****************"
  echo "_____END_TEST_KNOWN_GENERATION_____"
  exit 1
fi

