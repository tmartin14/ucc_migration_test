#  STOP - This project has been put on hold pending an upcoming update to Splunk's Add-On Builder project.   The AOB project will generate new versions of existing AOB TAs and this project should wait until that project completes in late Fall 2021.
____
If you still want to proceed and create a UCC-based version of an AOB TA this utility will work as is. 

# ucc Migration Test

This file contains source for a Unix shell script to perform a migration of modular inputs from a Splunk Add-On Builder(AOB) generated source base into a new Splunk UCC-based Add-On (a.k.a. TA).  Splunk Universal Configuration Console (UCC) format provides a consistent user interface across all Splunk Add-Ons.  

The script uses the helper functions from AOB's python3 libraries and merges the souce code from AOB-generated Inputs into a single file for each input.   There are a number of edits performed using sed, awk and grep that create a new TA in the package directory.

This script copies the globalConfig.json file to the root directory providing the proper setup to execute the [addonfactory-ucc-generator](https://github.com/splunk/addonfactory-ucc-generator) utility.

The script will make modifications to your python files and then prompt you to run ucc-gen, package the application for Splunkbase and submit the package to appInspect.  Each of these actions are recommended but optional and separate scripts are included to package the add-on and submit it to appInspect at later points in time.   

### Notes
- This utility has been tested for migrating Modular Inputs (both custom and REST calls) as well as Alert Actions. 
- The ucc-gen utility can be found here: [https://github.com/splunk/addonfactory-ucc-generator](https://github.com/splunk/addonfactory-ucc-generator)
- ucc-gen is installed using `$ pip3 install splunk-add-on-ucc-framework`

### Instructions
1. Clone this repository to your local machine
2. Copy your TA's entire directory into this directory `/ucc-migration_test/Splunk_TA_XXX`
3. Run the [convert.sh](./convert.sh) script from the root directory of this repository passing in the name of the TA’s directory    `./convert.sh Splunk_TA_XXX` 
    Your new source code will now be located in the `/ucc-migration_test/package` directory and is setup to run ucc-gen.
4. Accept the prompt to run `ucc-gen` with the `--ta-version` parameter OR exit and execute `ucc-gen` command from the `/ucc-migration_test` directory later.  The new TA will be written to a `ucc-migration_test/output` directory.
5. Accept the prompt package your TA into a .tgz file OR exit and package the TA later using the [package_app.sh](./package_app.sh) script included.
5. Upload your new TA from `ucc-migration_test/output/` to a Splunk server and test it out.
6. Accept the prompt to submit your app to Splunk's appInspect process OR exit and submit the TA later using the [submit_appInspect.sh](./submit_appInspect.sh) script included

### Helpful Link
[Splunk Cloud Vetting](https://dev.splunk.com/enterprise/docs/releaseapps/cloudvetting/)




