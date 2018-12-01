#!/usr/bin/env bash

# 20181201, based on: https://stackoverflow.com/questions/52373469/how-to-launch-junit-5-platform-from-the-command-line-without-maven-gradle

rm foo*
rm -fr target # remove directory, forcefully (with contents, and without asking. DO NOT TRY THIS AT HOME (or more importantly at /)
mkdir target


# This is some text file for test purposes
echo "Hello and goodbye" > foo

result=0 # contains sum of exit codes from various commands. Zero if everything successful

javac -d target Cryptest.java
let "result=$result+$?"

# Test compilation requires this classpath as it contains imports from junit jupiter
javac -d target -cp ~/APPS/java/junit/junit-platform-console-standalone-1.3.2.jar TestClass.java
let "result=$result+$?"

if [ "$result" -eq "0" ]
then
    echo "Compilation completed"
    echo "Running tests"
    java -jar ~/APPS/java/junit/junit-platform-console-standalone-1.3.2.jar --class-path target --scan-class-path # it searches for tests in compiled classes from given directory
else
    echo "Compilation failed"
fi
