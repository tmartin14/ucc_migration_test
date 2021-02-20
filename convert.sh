#! /bin/bash

##########    Find the FIXME section for the file name     & 
############   figure out how to make GlobalConfig.json have the right pathing -- it's looking here:  /opt/splunk/etc/appserver/static/js/build/globalConfig.json    

#Splunk_TA_New_Relic was used as the example source code for this project

# the LIB_DIR_COMMAND will be added after importing sys and os.  this needs to be in splunk_resthelper.base_modinput as well in each  input's code
LIB_DIR_COMMAND='sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))'
LIB_DIR_COMMAND='os.path.abspath("../..")'

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
# copy the existing globalConfig.json file to the root directory
# -------------------------------------------------------------------------------
cp ./package/appserver/static/js/build/globalConfig.json .

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
# move the 'helper files' from AOB into a new directory (splunk_resthelper)
# -------------------------------------------------------------------------------
mv ./package/bin/$AOB_TA_DIR_lowercase/aob_py3/splunk_aoblib ./package/bin/splunk_resthelper
mv ./package/bin/$AOB_TA_DIR_lowercase/aob_py3/modinput_wrapper/base_modinput.py ./package/bin/splunk_resthelper/.

# -------------------------------------------------------------------------------
# modify the packge names in base_modinput.py to reflect the new structure just created for splunk_resthelper
# -------------------------------------------------------------------------------
sed -i '' 's/from splunk_aoblib./from splunk_resthelper./g' ./package/bin/splunk_resthelper/base_modinput.py
sed -i '' 's/from solnlib.packages.splunklib import modularinput as smi/from splunklib import modularinput as smi/' ./package/bin/splunk_resthelper/base_modinput.py

# -------------------------------------------------------------------------------
# add the /lib directory to the base_modiput code
# -------------------------------------------------------------------------------
sed -i '' '1 a\ 
import import_declare_test


' ./package/bin/splunk_resthelper/base_modinput.py

# -------------------------------------------------------------------------------
# fix the directory structure lookup for globalConig.json   (AOB was 5 levels deep, now we're only 3) 
#    i.e.: config_path = "/opt/splunk/etc/apps/Splunk_TA_New_Relic/appserver/static/js/build/globalConfig.json"
# -------------------------------------------------------------------------------
sed -i '' 's/config_path = os.path.join(dirname(dirname(dirname(dirname(dirname(__file__))))),/config_path = os.path.join(dirname(dirname(dirname(__file__))),/' ./package/bin/splunk_resthelper/base_modinput.py
sed -i '' 's/basedir = dirname(dirname(dirname(dirname((dirname(__file__))))))/basedir = dirname(dirname(dirname(__file__)))/' ./package/bin/splunk_resthelper/setup_util.py


# -------------------------------------------------------------------------------
#          Now let's start processing the inputs
# -------------------------------------------------------------------------------
# let's work from the ./package/bin directory
cd ./package/bin

for OUTPUT in $(ls input_module_*.py | xargs -L1 | awk -F"input_module_" '{print $2}')
do
    echo Processing input named:   $OUTPUT
    # What do we need to do?
      # Copy the new imports and the input source code file into a varialbe
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
    #   1. The old import input_module_$OUTPUT as input_module statement 
    #   2. The old import $AOB_TA_DIR_lowercase_declare statement
    #   3. The old from solnlib.packages.splunklib import modularinput as smi  statement
    # -------------------------------------------------------------------------------
    new_input_source=$(echo "$new_input_source" | sed '/^import input_module_/d')
    new_input_source=$(echo "$new_input_source" | sed '/^import splunk_ta_new_relic_declare/d')        #FIX THIS  -- just testing with the real name
    new_input_source=$(echo "$new_input_source" | sed '/^from solnlib.packages.splunklib import modularinput as smi/d')
    #echo "$new_input_source" 


    # Change the package name for base_modinput.py
    new_input_source=$(echo "$new_input_source" | sed 's/modinput_wrapper.base_modinput/splunk_resthelper.base_modinput/g')

    # include the /lib directory in this Add-On
    #new_input_source=$(echo "$new_input_source" | sed '/^bin_dir = os.path.basename(__file__)/a sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))' )
    #new_input_source=$(echo "$new_input_source" | sed "s/^bin_dir = os.path.basename(__file__)/&\ntest/")
    #echo "$new_input_source" 

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

    # now we need to replace the AOB helper call with the actual collect_events logic from above
    new_input_source=${new_input_source/        input_module.collect_events(self, ew)/"$COLLECT_EVENTS"}
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

echo ##########  Items still missing    ########
echo 1. Does the new TA respect the proxy settings?
echo 2. Need to replace helper functions -- send_http_request, new_event, get_output_index, etc.
echo 3. What to do with checkpointing?
echo 4. go ahead and run ucc-gen 
echo
echo
echo

