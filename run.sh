#!/usr/bin/env bash

rm foo*

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
