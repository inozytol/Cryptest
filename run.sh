#!/usr/bin/env bash

# 20181226 modified to allow for packages
# 20181201, based on: https://stackoverflow.com/questions/52373469/how-to-launch-junit-5-platform-from-the-command-line-without-maven-gradle

. configuration.sh

rm -fr target # remove directory, forcefully (with contents, and without asking. DO NOT TRY THIS AT HOME (or more importantly at /)
mkdir target


# This is some text file for test purposes
echo "Hello and goodbye" > target/foo

result=0 # contains sum of exit codes from various commands. Zero if everything successful

javac -d target src/main/inozytol/dataencryption/Cryptest.java
let "result=$result+$?"

# Test compilation requires this classpath as it contains imports from junit jupiter
javac -d target -cp $JUNIT_JAR_PATH:.:target src/test/inozytol/dataencryption/TestClass.java
let "result=$result+$?"

if [ "$result" -eq "0" ]
then
    echo "Compilation completed"
    echo "Running tests"
    java -jar $JUNIT_JAR_PATH --class-path target --scan-class-path # it searches for tests in compiled classes from given directory
    echo "Running Cryptest"
    cd target
    java inozytol.dataencryption.Cryptest
    #rm -rf doc
    #mkdir doc
    #cd doc
    #javadoc ../Cryptest.java
    
else
    echo "Compilation failed"
fi
