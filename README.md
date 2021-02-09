# ucc Migration Test

This file contains source for a Unix (MacOS tested) shell script to perform a migration of modular inputs from a Splunk Add-On Builder(AOB) generated souce base into a new Splunk UCC-based Add-On (a.k.a. TA).  The script uses a template file and reads from the AOB python files for each input and emits a new python file with most of the code changes required remove the need for the AOB UI to maintain the code base.  

This utility creates a 'package' directory that can be fed into the ucc-gen pythn utility to create a stand-alone version of an existing TA.   There may be additional edits required after running these scripts, but the idea is to get you 90% of the way there. 

### Instructions

#### Setup:
1. Clone this repository to your local machine
2. Copy your TA's entire directory into this directory `/ucc-convert/Splunk_TA_XXX`
3. Run the convert.sh script from the root directory passing in the name of the TA’s directory    `./convert.sh Splunk_TA_XXX` 

Your new source code will now be located in the `/ucc-convert/package` directory and is setup to run ucc-gen.

Now you can execute ucc-gen and the new TA will be written to an `ucc-convert/output` directory.


#### Links

* [convert.sh](https://github.com/tmartin14/ucc_migration_test/convert.sh)
* [ucc_mod_input_template.py](https://github.com/tmartin14/ucc_migration_test/ucc_mod_input_template.py)



