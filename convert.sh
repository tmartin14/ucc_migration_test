#! /bin/bash
#    usage:    ./convert.sh TA_directory 

# Splunk_TA_New_Relic was used as the example source code for this project

# TODO:
#   add alert actions script modifications


# -------------------------------------------------------------------------------
#   Check input arguments and see if we're setup correctly
# -------------------------------------------------------------------------------
# Did the user specify the directory?   If not , get it now
if [ $# -eq 0 ]
  then
    read -p 'Enter the directory for the AOB TA (in this folder): ' AOB_TA_DIR 
  else
        AOB_TA_DIR="$1"
fi

### Check if the directory exists, if not, exit ###
if [ ! -d "$AOB_TA_DIR" ] 
then
    echo
    echo "Directory /$AOB_TA_DIR DOES NOT exists." 
    echo "   Usage:    ./convert.sh TA_Directory"
    echo
    exit 9999 # die with error code 9999
fi


#remove any traiing / from the dir name
AOB_TA_DIR=${AOB_TA_DIR%/}
AOB_TA_DIR_lowercase=$(echo "$AOB_TA_DIR" | tr '[:upper:]' '[:lower:]')

echo 
echo Converting "$AOB_TA_DIR"...
echo

# -------------------------------------------------------------------------------
#       Prepare this TA for ucc-gen
# -------------------------------------------------------------------------------

# -------------------------------------------------------------------------------
# create a 'package' directory and move all files from the existing TA into it
# -------------------------------------------------------------------------------
if [ -d ./package ]
then
    echo removing existing ./package directory
    rm -rf ./package
fi

echo Creating a new ./package directory 
echo 
mkdir package
cp -r ./$AOB_TA_DIR/ ./package

# -------------------------------------------------------------------------------
# copy the existing globalConfig.json file to the root directory and set the template type to use  (in our case, we'll use "input_with_helper" for all)
# -------------------------------------------------------------------------------
cp ./package/appserver/static/js/build/globalConfig.json .

# check to see if this globalConfig.json file has the "template": attribute   (if it does, there's no need to do anything)
check_for_template=$(grep -c '"template":' globalConfig.json)
if [[ $check_for_template -eq 0 ]]
then
    echo Updating globalConfig.json.   Adding \"template\":\"input_with_helper\" to each \"service\" 
    # get the beginning section of the globalConfig.json file and save it for later
    global_config_part1=$(cat globalConfig.json | sed -n  '/^            "services": \[/!p;//q')
    # get the services section of the json and add the template attribute to each input
    global_config_part2=$(cat globalConfig.json | sed -n '/^            "services": \[/,$p' | sed -E 's/"name": "([^"]+)",/"template":"input_with_helper",@                    "name": "\1",/g' | tr '@' '\n')
    # now join both parts back together to recreate globalConfig.json
    echo "$global_config_part1"$'\n'"$global_config_part2" > globalConfig.json 
else
    # no need for anything - this has already had the template added
    echo template attribute already exists.  No changes to globalConfig required.
fi
echo 

# -------------------------------------------------------------------------------
# ucc-based TA's will require the splunktaucclib library to be included in the build.  Add it here.
# -------------------------------------------------------------------------------
echo " -------------------------------------------"
echo "     Creating lib/requirements.txt file"
echo " -------------------------------------------"
mkdir ./package/lib
echo splunktaucclib==4.1.0 > ./package/lib/requirements.txt
echo "# " >> ./package/lib/requirements.txt
echo "#   The following list *may* also be required for your modular inputs to work.   " >> ./package/lib/requirements.txt
echo "#   Uncomment those that are required.   " >> ./package/lib/requirements.txt
echo "# " >> ./package/lib/requirements.txt 

# -------------------------------------------------------------------------------
# identify any additional imported libraries and add them to the requirements.txt file (exclude from xxx import yyy for now)
# -------------------------------------------------------------------------------
cat ./package/bin/input_module_*.py | grep import | grep -Ev '(from |import os|import sys|import time|import datetime|import json | import json, re)' | sed -n 's/.*import /#/p' | xargs -L1 | sort | uniq >>./package/lib/requirements.txt

# -------------------------------------------------------------------------------
#  for any 'import from' statements let's see if the library is included in the TA's /bin directory.    If NOT, let's add it to the requuirements.txt file
# -------------------------------------------------------------------------------
# let's work from the ./package/bin directory
cd ./package/bin

import_froms=$(cat ./input_module_*.py | grep import | grep from | sed -n 's/from //p' | xargs -L1 | sort | uniq | awk '{print $1}' | cut -d. -f1)
#echo "$import_froms"

included_dirs=$(ls -d */ | sed '/\./d;s%/$%%' )
#echo "$included_dirs"

for i in $import_froms
do
    included=false
    for x in $included_dirs
    do
        if [ "$i" == "$x" ] ; then
            included=true
        fi
    done
    if ! $included ; then
        echo "      Adding $i to requirements.txt"
        echo "#$i" >>../../package/lib/requirements.txt
    fi
done
echo "      Updating base64 to pybase64 in requirements.txt (if it exists)"
sed -i '' 's/base64/pybase64/g' ../../package/lib/requirements.txt
echo 
#  Remind the user to check for required libraries
echo "Please check ./package/lib/requirements.txt file for additional libraries you *may* need to include for your"
echo "modular inputs to work.  This script collects libraries that may or may not be needed and comments them all in "
echo "/package/lib/requirements.txt:"
cat ../../package/lib/requirements.txt
echo
echo "Finished processing for requirements.txt"
echo


# -------------------------------------------------------------------------------
#          Now let's start processing any alert actions
# -------------------------------------------------------------------------------
echo " ---------------------------------------"
echo "     Processing Alert Actions..."
echo " ---------------------------------------"
for MODALERT in $(ls ./*/modalert_*_helper.py | xargs -L1 | awk -v FS="(modalert_|_helper.py)" '{print $2}')
do
    echo Processing alert action named:   $MODALERT
    # -------------------------------------------------------------------------------
    # What do we need to do?
      # Copy the imports from the modalert_<name>_helper.py inot the <name>.py source code
      #    Change the import *_declare to import_declare_test
      #    Remove duplicate import statements  (lines 1-4 of <name>.py)
      # Remove the original process_event() function 
      # Copy the process_event() function from modalert_<name>_helper.py into the <name>.py source code  (and indent it)
      # Remove the import modalert_<name>_helper statement
      # Change the package name for alert_action_base to splunktaucclib.alert_action_base
      # Remove the helper directory     (dirs=(/testfolder/*/))
    # -------------------------------------------------------------------------------
    # Create variables to concatenate later
    IMPORT_STATIC="import import_declare_test"
    IMPORTS=$(cat ./*/modalert_${MODALERT}_helper.py | sed -n '1,/def process_event(/p' | sed '/import .*_declare/d' | sed '/# encoding = utf-8/d' | sed '$D' )
    PROCESS_EVENTS=$(cat ./*/modalert_${MODALERT}_helper.py |  sed -n '/def process_event(/,//p' | sed 's/^/    /' )

    # read in the old alert action file and remove the process_event function cocde
    alert_action=$(cat ${MODALERT}.py | sed '1,4d' | sed -e '/    def process_event(/,/if __name__ == "__main__"/{//!d;}')
    # concatenate the imports with the alert_action source
    alert_action="$IMPORT_STATIC"$'\n'"$IMPORTS"$'\n'"$alert_action"
    # add the process_events function
    alert_action=${alert_action/    def process_event(self, *args, **kwargs):/"$PROCESS_EVENTS"}
    # remove the reference to modalert_..._helper
    alert_action=$(echo "$alert_action" | sed '/import modalert_.*_helper/d')
    # change the pathing for alert_actions_base
    alert_action=$(echo "$alert_action" | sed 's/from alert_actions_base import ModularAlertBase/from splunktaucclib.alert_actions_base import ModularAlertBase/')
    # write out the new alert action file
    echo "$alert_action" > $MODALERT.py
    echo Done.   

done
echo Finished with Alert Actions




# -------------------------------------------------------------------------------
#          Now let's start processing any modular inputs
# -------------------------------------------------------------------------------
echo
echo " ---------------------------------------"
echo "     Processing Modular Inputs..."
echo " ---------------------------------------"
# -------------------------------------------------------------------------------
#    Remove any py files for any REST input that have an accompanying .cc.json file   -- ucc-gen will recreate the python file for us
# -------------------------------------------------------------------------------
for REST_API_INPUT in $(ls *.cc.json | sed -e 's/\.cc.json$//' 2> /dev/null)
do
    rm "$REST_API_INPUT".py 
done

for OUTPUT in $(ls input_module_*.py | xargs -L1 | awk -F"input_module_" '{print $2}')
do
    echo Processing input named:   $OUTPUT
    # What do we need to do?
      # Copy the new imports and the input source code file into a variable
      #   -- It'll be easier to read the file into a variable and then process the variable (since the variable won't care about newline characters)
      # Remove the old AOB-required import statements
      # Change the package name for base_modinput.py
      # Add the /lib directory in the add-on's source code
      # Set Single Instance Mode to false  (or copy it from $OUTUT)
      # Copy the validate_input code from AOB's template file (input_module_$OUTPUT)
      # Copy the collect_events code from AOB's template file (input_module_$OUTPUT)


    # -------------------------------------------------------------------------------
    #  get all of the import statements for this input that are NOT in our imports.py
    # -------------------------------------------------------------------------------
    cat ./input_module_$OUTPUT | grep import | grep -Ev '(import os|import sys|import time|import datetime|import json| import json, re)' | sed 's/^[ \t]*//' | sort | uniq >>./tmp_imports.py
    

    # -------------------------------------------------------------------------------
    # Add the imports from imports.py and the imports from this input to the current source code file
    # -------------------------------------------------------------------------------
    new_input_source=$(cat ../../imports.py tmp_imports.py $OUTPUT)
    rm tmp_imports.py


    # -------------------------------------------------------------------------------
    # Remove these:
    #   1. The old import $AOB_TA_DIR_lowercase_declare statement
    #   2. The old import input_module_$OUTPUT as input_module statement 
    #   3. The old from solnlib.packages.splunklib import modularinput as smi  statement
    #   4. The old import modinput_wrapper.base_modinput statement
    #   5. The old "Do Not Edit" lines from AOB code generation
    # -------------------------------------------------------------------------------
    #new_input_source=$(echo "$new_input_source" | sed "/^import ${AOB_TA_DIR_lowercase}_declare/d")
    new_input_source=$(echo "$new_input_source" | sed "/^import .*_declare$/d")
    new_input_source=$(echo "$new_input_source" | sed '/^import input_module_/d')
    new_input_source=$(echo "$new_input_source" | sed '/^from solnlib.packages.splunklib import modularinput as smi/d')
    new_input_source=$(echo "$new_input_source" | sed '/import modinput_wrapper.base_modinput/d')
    new_input_source=$(echo "$new_input_source" | sed '/Do not edit this file!!!/,/Add your modular input logic to file/d') 


    # -------------------------------------------------------------------------------
    # change the reference for base_modinput to use the name in the imports.py 
    # -------------------------------------------------------------------------------
    new_input_source=$(echo "$new_input_source" | sed 's/(modinput_wrapper.base_modinput./(base_mi./')

    # -------------------------------------------------------------------------------
    # set single instance mode to false and remove excess code from $OUTPUT
    # -------------------------------------------------------------------------------
    # Remove the if then logic and set the variable to False and fix the indentation
    new_input_source=$(echo "$new_input_source" | sed "/^        if 'use_single_instance_mode' /,/use_single_instance = False/{/use_single_instance = False/p;d;}" | sed 's/^            use_single_instance = False/        use_single_instance = False/')
    #echo "$new_input_source"


    # -------------------------------------------------------------------------------
    # get the validate_input code generated by AOB in the input_module_XXX file and insert it here  (with indentation & removal of 'helper')
    # -------------------------------------------------------------------------------
    VALIDATION=$(sed -n '/^def validate_input(helper, definition):/,/^def collect_events(/{ /^def collect_events(/d;/^def validate_input(helper/d;p;}' input_module_$OUTPUT | sed 's/def validate_input(helper, definition):/def validate_input(self, definition):/g' | sed 's/\(.*\)/    \1/' )
    #echo "$VALIDATION"
    
    # now we need to replace the AOB helper call with the actual validation logic from above
    new_input_source=${new_input_source/        input_module.validate_input(self, definition)/"$VALIDATION"}
    #echo "$new_input_source"


    # -------------------------------------------------------------------------------
    #   get the collect_events code from the input_module_XXX file and insert it here
    # -------------------------------------------------------------------------------
    COLLECT_EVENTS=$(sed -n '/^def collect_events(helper, ew):/,/^def /{ /^def collect_events(/p; /^def /d; p;}' input_module_$OUTPUT  | sed 's/def collect_events(helper, definition):/def collect_events(self, definition):/g' | sed 's/\(.*\)/    \1/')
    #echo COLLECT_EVENTS="$COLLECT_EVENTS"

    # now we need to replace the original call from to the 2nd file with the actual collect_events logic from above
    new_input_source=${new_input_source/        input_module.collect_events(self, ew)/"$COLLECT_EVENTS"}
    # and remove the old function call & comment
    new_input_source=$(echo "$new_input_source" | sed '/^    def collect_events(self, ew):/d')
    new_input_source=$(echo "$new_input_source" | sed '/^        """write out the events"""/d')
    #echo "$new_input_source"

    # set the ta_config filename
    new_input_source=${new_input_source//CONF_NAME/CONF_NAME = \""$AOB_TA_DIR_lowercase"\"}

    # Overwrite out the mod input source code file with this new code
    echo "$new_input_source" > $OUTPUT
    echo Done.   
done
echo Finished with Modular Inputs
echo

# OK, let's get back to the main directory
cd ../..

echo
echo " ----------------------------------------------------------------"
echo "     Cleaning Up... Removing files that are no longer needed "
echo " ----------------------------------------------------------------"
# remove AOB files and other things that will be automatically recreated with ucc-gen
rm ./package/default/addon_builder.conf 
rm ./package/default/*_settings.conf
rm ./package/metadata/local.meta 2> /dev/null
rm ./package/README.txt 2> /dev/null
rm ./package/bin/*.pyc 2> /dev/null
rm ./package/bin/__pycache__ 2> /dev/null
rm ./package/bin/*_rh*.py 2> /dev/null
rm ./package/bin/input_module_*.py 2> /dev/null

rm -rf ./package/locale
rm -rf ./package/README
rm -rf ./package/bin/*/aob_py*/
rm -rf ./package/bin/*_declare.py
rm ./package/bin/*/modalert_*_helper.py 2> /dev/null
rm ./package/bin/*/alert_actions_base.py 2> /dev/null
rm ./package/bin/*/cim_actions.py 2> /dev/null
rm ./package/bin/*/logging_helper.py 2> /dev/null
#rm -rf ./package/default/data     --> may need to re-add this directory removal when UCC5 hits  (react framework)
#rm -rf ./package/appserver        --> removing 4/14 to keep any custom js, images, etc.
find ./package/bin/ -empty -type d -delete     # remove any empty directories from /bin
echo Done. 

# Check all *.py files for tab indentation errors
echo
got_tabs=$(grep -n '\t' ./package/bin/*.py | wc -l)
if [ $got_tabs != "0" ] 
  then
    echo "Checking for potential issues with tabs and/or indentation.   (python3 doesn't like mixing tabs and spaces)"
    echo "  If found, these must be fixed before running ucc-gen.  "
    grep -n '\t' ./package/bin/*.py 
fi  
echo
echo Finished.
echo 
echo