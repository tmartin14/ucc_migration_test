#! /bin/bash

# Splunk_TA_New_Relic was used as the example source code for this project

# TODO:
#   make it work for python2 ???
#   fix the duplicated imports between the TA and imports.py
#   Test to see if the new TA respects the proxy settings
#   Test checkpointing
#   fix inputs that are NOT mod_input_XXX.py



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
    echo "Directory /$AOB_TA_DIR DOES NOT exists." 
    exit 9999 # die with error code 9999
fi


#remove any traiing / from the dir name
AOB_TA_DIR=${1%/}
AOB_TA_DIR_lowercase=$(echo "$AOB_TA_DIR" | tr '[:upper:]' '[:lower:]')

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

echo Creating a new ./package directory for your new ucc-based TA 
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

# -------------------------------------------------------------------------------
# ucc-based TA's will require the splunktaucclib library to be included in the build.  Add it here.
# -------------------------------------------------------------------------------
mkdir ./package/lib
echo splunktaucclib==4.0.7 > ./package/lib/requirements.txt

# -------------------------------------------------------------------------------
# identify any additional imported libraries and add them to the requirements.txt file 
# -------------------------------------------------------------------------------
cat ./package/bin/input_module_*.py | grep import | grep -Ev '(import os|import sys|import time|import datetime|import json, re)' | sed -n 's/.*import //p' | xargs -L1 | sort | uniq >>./package/lib/requirements.txt

# -------------------------------------------------------------------------------
#          Now let's start processing the inputs
# -------------------------------------------------------------------------------
# let's work from the ./package/bin directory
cd ./package/bin

# -------------------------------------------------------------------------------
#    Remove any py files for any REST input that have an accompanying .cc.json file   -- ucc-gen will recreate the python file for us
# -------------------------------------------------------------------------------
for REST_API_INPUT in $(ls *.cc.json | sed -e 's/\.cc.json$//')
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
    # Start with the new imports added to our current source code file
    # -------------------------------------------------------------------------------
    new_input_source=$(cat ../../imports.py $OUTPUT)
    #echo "$new_input_source"

    # -------------------------------------------------------------------------------
    # Remove these:
    #   1. The old import $AOB_TA_DIR_lowercase_declare statement
    #   2. The old import input_module_$OUTPUT as input_module statement 
    #   3. The old from solnlib.packages.splunklib import modularinput as smi  statement
    #   4. The old import modinput_wrapper.base_modinput statement
    # -------------------------------------------------------------------------------
    new_input_source=$(echo "$new_input_source" | sed "/^import ${AOB_TA_DIR_lowercase}_declare/d")
    new_input_source=$(echo "$new_input_source" | sed '/^import input_module_/d')
    new_input_source=$(echo "$new_input_source" | sed '/^from solnlib.packages.splunklib import modularinput as smi/d')
    new_input_source=$(echo "$new_input_source" | sed '/import modinput_wrapper.base_modinput/d')

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

# OK, let's get back to the main directory
cd ../..

echo
echo Cleaning Up... Removing files that are no longer needed
# remove AOB files and other things that will be automatically recreated with ucc-gen
rm ./package/default/addon_builder.conf 
rm ./package/default/*_settings.conf
rm ./package/metadata/local.meta 2> /dev/null
rm ./package/README.txt 2> /dev/null
rm ./package/bin/*.pyc 2> /dev/null
rm ./package/bin/__pycache__ 2> /dev/null
rm ./package/bin/input_module_*.py 
rm ./package/bin/${AOB_TA_DIR}_rh*.py 

rm -rf ./package/locale
rm -rf ./package/default/data
rm -rf ./package/README
rm -rf ./package/appserver
rm -rf ./package/bin/${AOB_TA_DIR_lowercase}
rm -rf ./package/bin/${AOB_TA_DIR_lowercase}_declare.py

echo Finished.
echo 
echo
echo