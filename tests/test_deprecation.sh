#!/bin/bash
echo 
echo
echo "______START_TEST_DEPRECATION_____"
./mypass -no -f./testing < ./new_user1 >> /dev/null
./mypass -aalias -f./testing -ppassword >> /dev/null
for num in {2..253}; do
  ./mypass -galias -f./testing -d -ppassword >> /dev/null
  if [[ $? -ne 0 ]]; then
    echo "test_deprecate"
    echo "deprecation $num failed"
    echo "**************FAIL**************"
    exit 1
  fi
done

./mypass -galias -f./testing -d -ppassword >> /dev/null
if [[ $? -eq 0 ]]; then
  echo "test_deprecate"
  echo "Should have rejected this deprecation test one"
  echo "****************FAIL****************"
  exit 1
fi

./mypass -galias -f./testing -D1 -ppassword >> /dev/null
if [[ $? -ne 0 ]]; then
  echo "test_deprecate"
  echo "Set deprecation failed"
  echo "*****************FAIL*****************"
  exit 1
fi

./mypass -galias -f./testing -D0 -ppassword >> /dev/null
if [[ $? -eq 0 ]]; then
  echo "test_deprecate"
  echo "Should have rejected this deprecation set D0"
  echo "****************FAIL****************"
  exit 1
fi

./mypass -galias -f./testing -D255 -ppassword >> /dev/null
if [[ $? -eq 0 ]]; then
  echo "test_deprecate"
  echo "Should have rejected this deprecation set D255"
  echo "****************FAIL****************"
  exit 1
fi

./mypass -galias -f./testing -D1000 -ppassword >> /dev/null
if [[ $? -eq 0 ]]; then
  echo "test_deprecate"
  echo "Should have rejected this deprecation set D1000"
  echo "****************FAIL****************"
  exit 1
fi
echo "*****************PASSES****************"
echo "______END_TEST_DEPRECATION_____"
exit 0

