# ucc Migration Test

This file contains source for a Unix (MacOS tested) shell script to perform a migration of modular inputs from a Splunk Add-On Builder(AOB) generated souce base into a new Splunk UCC-based Add-On (a.k.a. TA).  The script copies the helper functions from AOB's pythn3 libraries and converts the appropriate code to a new directory in the new TA (/bin/splunk_resthelper).   There are a number of edit s performed using sed, awk and grep that create a new TA in the package directory.  

This script creates the package directory and moves the globalConfig.json file to the root directory providing the proper setup to execute the [addonfactory-ucc-generator](https://github.com/splunk/addonfactory-ucc-generator) utility.

There may be additional edits required after running these scripts, but the idea is to get you 90+% of the way there. 

### Instructions

#### Usage:
1. Clone this repository to your local machine
2. Copy your TA's entire directory into this directory `/ucc-migration_test/Splunk_TA_XXX`
3. Run the convert.sh script from the root directory of this repository passing in the name of the TA’s directory    `./convert.sh Splunk_TA_XXX` 
    Your new source code will now be located in the `/ucc-migration_test/package` directory and is setup to run ucc-gen.

4. Execute `ucc-gen` and the new TA will be written to an `ucc-migration_test/output` directory.
5. Upload your new TA from `ucc-migration_test/output/Splunk_TA_XXX` into your Splunk server's /etc/apps directory and try it out.


#### Links
* [convert.sh](https://github.com/tmartin14/ucc_migration_test/convert.sh)




