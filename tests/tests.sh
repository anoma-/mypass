#! /bin/bash

cd .. &&
make &&
mv ./mypass ./tests/ &&
cd tests &&
./test_add_remove.sh && 
./test_deprecation.sh &&
./test_known_generation.sh &&
./test_same_new_user_input.sh &&
./test_import.sh
rm ./mypass
rm ./testing
rm ./key
