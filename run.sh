#!/usr/bin/env bash

rm foo
rm foo2
rm foo_crypt
rm foo_decrypt

echo "Hello and goodbye" > foo

javac Cryptest.java

if [ "$?" -eq "0" ]
then
    echo "Compilation completed"
    echo "Running tests"
    java Cryptest
else
    echo "Compilation failed \n"
fi
