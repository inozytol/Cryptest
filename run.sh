#!/usr/bin/env bash

# 20181226 modified to allow for packages
# 20181201, based on: https://stackoverflow.com/questions/52373469/how-to-launch-junit-5-platform-from-the-command-line-without-maven-gradle

. configuration.sh

rm -fr target # remove directory, forcefully (with contents, and without asking. DO NOT TRY THIS AT HOME (or more importantly at /)
mkdir target


# This is some text file for test purposes
echo "Hello and goodbye" > target/foo

result=0 # contains sum of exit codes from various commands. Zero if everything successful

javac -d target -cp $LOG4J_JAR_API_PATH:.:target src/main/inozytol/dataencryption/Cryptest.java
let "result=$result+$?"

# Test compilation requires this classpath as it contains imports from junit jupiter
javac -d target -cp $JUNIT_JAR_PATH:$LOG4J_JAR_CORE_PATH:.:target src/test/inozytol/dataencryption/TestClass.java
let "result=$result+$?"

if [ "$result" -eq "0" ]
then
    echo "Compilation completed"
    echo "Running tests"
    java -jar $JUNIT_JAR_PATH --class-path $LOG4J_JAR_API_PATH:$LOG4J_JAR_CORE_PATH:.:target --scan-class-path # it searches for tests in compiled classes from given directory
    echo "Running Cryptest"
    java -cp $LOG4J_JAR_API_PATH:$LOG4J_JAR_CORE_PATH:.:target inozytol.dataencryption.Cryptest
    if [ $? -eq "0" ]
    then
	
	rm -rf doc
	mkdir doc
	cd doc
	javadoc -cp $LOG4J_JAR_API_PATH:.:../target ../src/main/inozytol/dataencryption/*
	cd ../
	cd target
	jar cvf Cryptest.jar inozytol/dataencryption/Cryptest.class
	cd ../
    fi

    #rm -rf doc
    #mkdir doc
    #cd doc
    #javadoc ../Cryptest.java
    
else
    echo "Compilation failed"
fi
