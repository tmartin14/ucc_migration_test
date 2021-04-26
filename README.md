#  STOP - This project has been put on hold pending an upcoming update to Splunk's Add-On Builder project.   This project will generate new versions of older TAs and this project should wait until that project completes in late June or earlly July 2021.
____


# ucc Migration Test

This file contains source for a Unix shell script to perform a migration of modular inputs from a Splunk Add-On Builder(AOB) generated souce base into a new Splunk UCC-based Add-On (a.k.a. TA).  

The script uses the helper functions from AOB's python3 libraries and merges the souce code from AOB-generated Inputs into a single file for each input.   There are a number of edits performed using sed, awk and grep that create a new TA in the package directory.    

This script creates a `package` directory and moves the globalConfig.json file to the root directory providing the proper setup to execute the [addonfactory-ucc-generator](https://github.com/splunk/addonfactory-ucc-generator) utility.

There may be additional edits required after running these scripts, but the idea is to get you 90+% of the way there. 

### Notes
- This utility has not yet been tested for migrating Alert Actions.  It has only been tested with custom python inputs and REST API calls previously created in Splunk Add-On Builder(AOB)
- The ucc-gen utility can be found here: [https://github.com/splunk/addonfactory-ucc-generator](https://github.com/splunk/addonfactory-ucc-generator)
- ucc-gen is installed using `$ pip3 install splunk-add-on-ucc-framework`

### Instructions
1. Clone this repository to your local machine
2. Copy your TA's entire directory into this directory `/ucc-migration_test/Splunk_TA_XXX`
3. Run the [convert.sh](./convert.sh) script from the root directory of this repository passing in the name of the TA’s directory    `./convert.sh Splunk_TA_XXX` 
    Your new source code will now be located in the `/ucc-migration_test/package` directory and is setup to run ucc-gen.
4. Execute `ucc-gen` command from the `/ucc-migration_test` directory and the new TA will be written to a `ucc-migration_test/output` directory.
5. Upload your new TA from `ucc-migration_test/output/Splunk_TA_XXX` into your Splunk server's /etc/apps directory and try it out.
6. When you're ready, Package your app using the [package_app.sh](./package_app.sh)
7. Submit your app to Splunk's appInspect or validation and Splunk Cloud vetting process using [the script in this repo](https://github.com/tmartin14/splunk-appInspect-helper)



