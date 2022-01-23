#!/bin/bash

################################################################################
##                       Cloud Computing Course                               ##
##                            Runner Script                                   ##
##                                                                            ##
##            Copyright 2021-2022: Cloud Computing Course                     ##
##                     Carnegie Mellon University                             ##
##   Unauthorized distribution of copyrighted material, including             ##
##  unauthorized peer-to-peer file sharing, may subject the student           ##
##  to the fullest extent of Carnegie Mellon University copyright policies.   ##
################################################################################

################################################################################
##                      README Before You Start                               ##
################################################################################
# Fill in the functions below for each question.
# You may use any programming language(s) in any question.
# You may use other files or scripts in these functions as long as they are in
# the submission folder.
# All files MUST include source code (e.g., do not just submit jar or pyc files).
#
# We will suggest tools or libraries in each question to enrich your learning.
# You are allowed to solve questions without the recommended tools or libraries.
#
# The colon `:` is a POSIX built-in basically equivalent to the `true` command,
# REPLACE it with your own command in each function.
# Before you fill in your solution, DO NOT remove the colon or the function will
# break because the bash functions are empty!


################################################################################
##                          Setup & Cleanup                                   ##
################################################################################

setup() {
  # Fill in this helper function to do any setup if you need to.
  #
  # This function will be executed once at the beginning of the grading process.
  # Other functions may be executed repeatedly in arbitrary order.
  # Make use of this function to reduce any unnecessary overhead and to make your
  # code behave consistently.
  #
  # e.g., You should compile Java code in this function.
  #
  # However, DO NOT use this function to solve any questions or to
  # generate any intermediate output.
  #
  # Examples:
  # mvn clean package
  #
  # Standard output format:
  # No standard output needed

  # convert the notebook into an executable Python script (DO NOT remove)
  jupyter nbconvert data_analysis.ipynb --to python --TagRemovePreprocessor.remove_input_tags excluded_from_script
  mvn package
  # Add more setup below if you need to

}

cleanup() {
  # Fill this helper function to clean up if you need to.
  #
  # This function will be executed once at the end of the grading process.
  # Other functions might be executed repeatedly in arbitrary order.
  #
  # Examples:
  # mvn clean
  #
  # Standard output format:
  # No standard output needed
  mvn clean
}

################################################################################
##                        Data Pre-processing                                 ##
################################################################################

filter() {
  # (45 points)
  #
  # Question:
  # DO NOT MODIFY THIS FUNCTION. It has already been filled out for you.
  #
  # The following description is just for your edification.
  # This functions filters an input stream read from the dataset
  # `pageviews-20180310-000000.gz' using a compiled jar file.
  # You implemented the DataFilter class to write the output into a file named
  # 'output'
  #
  # Instead of working with uncompressed data, this function "pipes" the data
  # from zcat, a utility which can read a compressed to StdOut, into the above
  # mentioned jar file.
  #
  # Hint for Java users in later questions:
  # WE DO NOT compile java code in this function,
  # Instead, we put the `mvn` command in the setup() function
  #
  # Standard output format:
  # No standard output needed
  zcat pageviews-20180310-000000.gz | java -cp target/data-filter.jar edu.cmu.scs.cc.Main
}

################################################################################
##                             Grep Basics                                    ##
################################################################################
# Grep is a command-line tool for searching plain text that matches a regular
# expression. It will print out all the matching lines by default. It also has
# the option to print out the number of matching lines. It is a simple yet
# powerful tool for searching information.
#
# Note: the input file used in all the questions below is `output`

q1() {
  # (3 points) search a substring in a file with grep
  #
  # Question:
  # Search the output file and print the lines that contain "cloud"
  # as a substring (case insensitive).
  #
  # `grep`, named after "Global/Regular Expression/Print", prints lines that
  # contain a match for a pattern.
  #
  # Try searching the options of GNU grep from the manual page,
  # 1. Display the manual page for "grep": man grep
  # 2. Hit "/", type in the keyword and hit "Enter"
  # 3. Hit "n" to find the next match and "N" to find the previous match
  #
  # Hint: search keyword "case" to find all the options related to "case"
  #
  # Now you can solve the question using:
  # grep options "cloud" input_file
  #
  # Standard output format:
  # <matched_line>
  # <matched_line>
  #
  :
}

q2() {
  # (3 points) search word with grep
  #
  # Question:
  # How many articles are there in the filtered dataset with titles that include
  # "cloud" as a word instead of a substring (case insensitive)?
  #
  # A "cloud" substring must meet two requirements at the same time to be
  # qualified as a word:
  # 1. word boundary before "cloud":
  # "cloud" is at the beginning of the line, or preceded by a non-word
  # constituent character.
  # 2. word boundary after "cloud":
  # Similarly, "cloud" must be either at the end of the line or followed by
  # a non-word constituent character.
  #
  # Word-constituent characters are letters, digits, and the underscore,
  # i.e. [a-zA-Z_0-9]
  #
  # To understand the concept of word boundary, please read:
  # http://www.regular-expressions.info/wordboundaries.html
  #
  # Valid examples:
  # Cloud	45
  # Asperitas_(cloud)	9
  # Cloud-based_networking	4
  #
  # Invalid examples:
  # Cloud_computing	14
  # SoundCloud 43
  # Cloud9_(team)	1
  #
  #
  # Search the options of GNU grep that:
  # 1. suppress normal output which will print the matched lines, and print a
  # count of matching lines instead
  # 2. select lines containing matches that form whole words instead of
  # substrings
  # 3. search in a case-insensitive way
  #
  # Hint:
  # 1. search keyword "count" in the grep manual page
  # 2. search keyword "word" in the grep manual page
  #
  # Solve the question using:
  # grep options "cloud" input_filename
  #
  # Standard output format:
  # <number>
  :
}

q3() {
  # (4 points) match the position of pattern with grep using anchors
  #
  # Anchors in regular expressions are used to match a pattern at a certain position
  #
  # Question:
  # Print all the lines that start with the substring "cloud" (case insensitive)
  #
  # Valid examples:
  # Cloud	45
  # Cloud_computing	14
  # Cloud9_(team)	1
  # Cloud-based_networking	4
  #
  # Invalid examples:
  # Asperitas_(cloud)	9
  # SoundCloud 43
  #
  # Search the options of GNU grep that:
  # 1. interpret the pattern as a Perl regex for additional functionality
  #
  # Hint:
  # search keyword "perl" in the grep manual page to find the option
  # that enables perl regex
  #
  # Here are some clues related to the syntax of regular expressions in Perl:
  # 1. learn how to use an anchor in a regular expression
  #    https://www.regular-expressions.info/anchors.html
  #
  # Solve the question using:
  # grep options pattern input_filename
  #
  # Standard output format:
  # <matched_line>
  # <matched_line>
  # ...
  :
}


################################################################################
##                           Data Analysis                                    ##
################################################################################
# In the following sections, you should write a function to compute the answer
# and print it to StdOut for each question.
#
# Finish the related primers first if you have not done so, as they will help
# you get well prepared for the questions.
#
# WARNING:
# Treat every function as an independent and standalone program.
# Any question below should not depend on the result or the intermediate
# output of another function.
#
# Note: the input file used in all the questions below is `output`

q4() {
  # (4 points) simple data filtering with awk
  #
  # Question:
  # Print all the records in the filtered output with view counts
  # greater than 5000
  #
  # Learn what built-in variables are available in awk
  # What do "$0, $1, $2, ... " represent in awk
  # https://www.tutorialspoint.com/awk/awk_built_in_variables.htm
  #
  # Learn the basic syntax and control flow in awk
  # and how to use the if statement
  # https://www.tutorialspoint.com/awk/awk_control_flow.htm
  #
  # Fill in the template and finish the solution:
  # awk '{ if (condition) { action } }' input_file
  #
  # Standard output format:
  # <record with view count greater than 5000>
  # <record with view count greater than 5000>
  # <record with view count greater than 5000>
  # ...
  :
}

q5() {
  # (4 points) simple data processing with awk
  #
  # Question:
  # How many requests were made to English Wikipedia in the hour?
  # (i.e., the sum of the accesses in the filtered file, `output`)
  #
  # learn the workflow of awk
  # https://www.tutorialspoint.com/awk/awk_workflow.htm
  #
  # e.g., to print the sum of the first column of input_file
  #     awk '{cnt+=$1} END {print cnt}' input_file
  #
  # Fill in the template and finish the solution:
  # awk '{ action } END { end_action }' input_file
  #
  # Standard output format:
  # <number>
  :
}

################################################################################
# q6 - q9 should be implemented in data_analysis.ipynb
#
# Hint: You may need to implement the following functions so
#       they are encoding-aware.
#       Refer to the "Be cautious about implicit reliance on your environment"
#       section in the writeup.
#       If you don't see any output for these questions, are you running THIS
#       file with your virtual environment activated?
# DO NOT MODIFY THE BELOW FUNCTIONS

q6() {
  python3 data_analysis.py -r q6
}

q7() {
  python3 data_analysis.py -r q7
}

q8() {
  python3 data_analysis.py -r q8
}

q9() {
  python3 data_analysis.py -r q9
}

################################################################################
##                    DO NOT MODIFY ANYTHING BELOW                            ##
################################################################################

declare -ar questions=( "filter" "q1" "q2" "q3" "q4" "q5" "q6" "q7" "q8" "q9")
declare -ar mapred=( "map" "reduce" )

readonly usage="This program is used to execute your solution.
Usage:
./runner.sh to run all the questions
./runner.sh -r <question_id> to run one single question
./runner.sh -s to run setup() function
./runner.sh -c to run cleanup() function
Example:
./runner.sh -r q1 to run q1"

contains() {
  local e
  for e in "${@:2}"; do
    [[ "$e" == "$1" ]] && return 0;
  done
  return 1
}

while getopts ":hr:sc" opt; do
  case ${opt} in
    h)
      echo "$usage" >&2
      exit
    ;;
    s)
      setup
      echo "setup() function executed" >&2
      exit
    ;;
    c)
      cleanup
      echo "cleanup() function executed" >&2
      exit
    ;;
    r)
      question=$OPTARG
      if contains "$question" "${questions[@]}"; then
        answer=$("$question")
        echo -n "$answer"
      else
        if contains "$question" "${mapred[@]}"; then
          "$question"
        else
          echo "Invalid question id" >&2
          echo "$usage" >&2
          exit 2
        fi
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
  echo "The answers generated by executing your solution are: " >&2

  for question in "${questions[@]}"; do
    echo "$question:"
    result="$("$question")"
    if [[ "$result" ]]; then
      echo "$result"
    else
      echo ""
    fi
  done
  cleanup 1>&2
  echo "cleanup() function executed" >&2
  echo "If you feel these values are correct please run:" >&2
  echo "./submitter" >&2
else
  echo "Invalid usage" >&2
  echo "$usage" >&2
  exit 2
fi
