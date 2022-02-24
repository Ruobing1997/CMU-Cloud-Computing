#!/bin/bash

################################################################################
##                       Cloud Computing Course                               ##
##            Runner Script for Heterogenous Storage on the Cloud             ##
##                                                                            ##
##            Copyright 2021-2022: Cloud Computing Course                     ##
##                     Carnegie Mellon University                             ##
##   Unauthorized distribution of copyrighted material, including             ##
##  unauthorized peer-to-peer file sharing, may subject the students          ##
##  to the fullest extent of Carnegie Mellon University copyright policies.   ##
################################################################################

################################################################################
##                      README Before You Start                               ##
################################################################################
# Fill in the functions below for each question.
# You may use any programming language(s) in any question.
# You may use other files or scripts in these functions as long as they are in
# the submission folder.
# All files MUST include source code (e.g. do not just submit jar or pyc files).
#
# We will suggest tools or libraries in each question to enrich your learning.
# You are allowed to solve questions without the recommended tools or libraries.
#
# The colon `:` is a POSIX built-in basically equivalent to the `true` command,
# REPLACE it with your own command in each function.
# Before you fill your solution,
# DO NOT remove the colon or the function will break because the bash functions
# may not be empty!


################################################################################
##                                   Setup                                    ##
################################################################################

setup() {
  # Fill in this helper function to do any setup if you need to.
  #
  # This function will be executed once at the beginning of the grading process.
  # Other functions might be executed repeatedly in arbitrary order.
  # Make use of this function to reduce unnecessary overhead and to make your
  # code behave consistently.
  #
  # e.g. You should compile Java code in this function.
  #
  # However, DO NOT use this function to solve any question or
  # generate any intermediate output.
  #
  # Examples:
  # javac *.java
  # mvn clean package
  # pip3 install -r requirements.txt
  #
  # Standard output format:
  # No standard output needed
  mvn clean package -Dmaven.test.skip=true
}

################################################################################
##                           SQL and Pandas                                   ##
################################################################################
# Note: Solve this question AFTER you finished reading the
# MySQL section of the writeup
q1() {
  # Read a SQL table to a DataFrame and calculate descriptive
  # statistics
  #
  # Question:
  # Print column-wise descriptive statistics of review count and stars
  # columns in businesses table
  #
  # 1. the metrics required are as follows (in a tabular view):
  #       review_count     stars
  # count     ...           ...
  # mean      ...           ...
  # std       ...           ...
  # min       ...           ...
  # 25%       ...           ...
  # 50%       ...           ...
  # 75%       ...           ...
  # max       ...           ...
  # 2. the statistics result should be in CSV format
  # 3. format each value to 2 decimal places
  #
  # A DataFrame represents a tabular, spreadsheet-like data structure containing
  # an ordered collection of columns.
  # As you notice, there is an intuitive relation between a DataFrame and a SQL
  # table.
  #
  # Use the pandas lib to read a SQL table and generate descriptive statistics
  # without having to reinvent the wheel. You will realize how easy it is to
  # generate statistics using pandas on SQL tables.
  #
  # Hints:
  # 1. pandas.read_sql can read the result of a query on a sql database
  # into a DataFrame
  # 2. figure out the sql query which can read the required columns from the
  #  reviews table into the DataFrame
  # 3. figure out how to establish a sql connection using MySQLdb
  # 3. figure out the method of pandas.DataFrame which can calculate
  # descriptive statistics
  # 4. figure out the parameter of pandas.DataFrame.to_csv to format the
  # floating point numbers.
  #
  # You can solve the problem by filling in the correct method or parameters
  # to the following Python code:
  #
  # import MySQLdb
  # import pandas as pd
  # import sys
  #
  # conn = MySQLdb.connect(<params>) # build the MySQL connection
  # query = "<sql_query>" # the SQL query
  # df = pd.read_sql(query, con=conn)
  # df.<method>.to_csv(sys.stdout, encoding='utf-8', <params>)
  #
  # You may want to create a separate python script and execute
  # the script in this method.
  #
  # Standard output format:
  # count,174567.00,174567.00
  # mean,30.14,3.63
  # std,98.21,1.00
  # min,3.00,1.00
  # 25%,4.00,3.00
  # 50%,8.00,3.50
  # 75%,23.00,4.50
  # max,7361.00,5.00
  python3 q1.py
}


################################################################################
##                    DO NOT MODIFY ANYTHING BELOW                            ##
################################################################################
RED_FONT='\033[0;31m'
NO_COLOR='\033[0m'
declare -ar mysql=( "q2" "q3" "q4" "q5" "q6" "q7" "q8")
declare -ar hbase=( "q9" "q10" "q11" "q12")
declare -ar rowkey_design=( "rowkey-design" )
declare questions=("q1" "${mysql[@]}" "${hbase[@]}")

last=${questions[$((${#questions[*]}-1))]}
readonly last
readonly usage="This program is used to execute your solution.
Usage:
./runner.sh to run all the questions
./runner.sh -r <question_id> to run one single question
./runner.sh -s to run setup() function
./runner.sh -t <task_name> to run all questions in a task
Example:
./runner.sh -r q1 to run q1
./runner.sh -t mysql/hbase"

contains() {
  local e
  for e in "${@:2}"; do
    [[ "$e" == "$1" ]] && return 0;
  done
  return 1
}

run() {
  if contains "$1" "${mysql[@]}"; then
    echo -n "$(java -cp target/database_tasks.jar edu.cmu.cs.cloud.MySQLTasks "$1")"
  elif contains "$1" "${hbase[@]}"; then
    echo -n "$(java -cp target/database_tasks.jar edu.cmu.cs.cloud.HBaseTasks "$1")"
  else
    echo -n "$("$1")"
  fi
}

while getopts ":hsr:t:" opt; do
  case $opt in
    h)
      echo "$usage" >&2
      exit
      ;;
    s)
      setup
      echo "setup() function executed" >&2
      exit
      ;;
    r)
      question=$OPTARG
      if contains "$question" "${questions[@]}"; then
        run "$question"
      elif contains "$question" "${rowkey_design[@]}"; then
        java -cp target/database_tasks.jar edu.cmu.cs.cloud.HBaseTasks "rowkey-design"
      else
        echo "Invalid question id" >&2
        echo "$usage" >&2
        exit 2
      fi
      exit
      ;;
    t)
      task=$OPTARG
      if [ "$task" == "mysql" ]; then
        # mysql task"
        run "q1"
        echo ""
        for question in "${mysql[@]}"; do
          run "$question"
          echo ""
        done
      elif [ "$task" == "hbase" ]; then        # hbase task
        for question in "${hbase[@]}"; do
          run "$question"
          echo ""
        done
        java -cp target/database_tasks.jar edu.cmu.cs.cloud.HBaseTasks "rowkey-design"
      else
        echo "Invalid task: $task" >&2
      fi
      exit
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      echo "$usage" >&2
      exit 2
      ;;
  esac
done

if [ -z "$1" ]; then
  setup 1>&2
  echo "setup() function executed" >&2
  echo -e "The ${RED_FONT}JSON escaped${NO_COLOR} answers generated by executing your solution are: " >&2
  echo "{"
  for question in "${questions[@]}"; do
    echo -n ' '\""$question"\":"$(run "$question" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()))')"
    if [[ "${question}" == "$last" ]]; then
      echo ""
    else
      echo ","
    fi
  done
  echo "}"
  echo ""
  mvn test >&2 && mvn jacoco:report >&2
  echo "If you feel these values are correct please run:" >&2
  echo "./submitter" >&2
else
  echo "Invalid usage" >&2
  echo "$usage" >&2
  exit 2
fi
