# ucc Migration Test

This file contains source for a Unix (MacOS tested) shell script to perform a migration of modular inputs from a Splunk Add-On Builder(AOB) generated souce base into a new Splunk UCC-based Add-On (a.k.a. TA).  The script uses a template file and reads from the AOB python files for each input and emits a new python file with most of the code changes required remove the need for the AOB UI to maintain the code base.  

This utility creates a 'package' directory that can be fed into the ucc-gen pythn utility to create a stand-alone version of an existing TA.   There may be additional edits required after running these scripts, but the idea is to get you 90% of the way there. 

### Instructions

#### Setup:
1. Create a new directory to work in `/ucc-convert`
2. Create a shell script in this directory using the source below  `/ucc-convert/convert.sh`
3. Copy the `ucc_mod_input_template.py` file into the directory 
      `/ucc-convert/`
4. Download the TA and expand it into the folder `/ucc-convert/Splunk_TA_XXX`
5. Run the script from the current directory passing in the name of the TA’s directory    `./convert Splunk_TA_XXX` 

Your new TA will now be located in the `/ucc-convert/package` directory and is setup to run ucc-gen.

Now you can execute ucc-gen.


####Links

* [convert.sh](https://github.com/tmartin14/ucc_migration_test/convert.sh)
* [ucc_mod_input_template.py](https://github.com/tmartin14/ucc_migration_test/ucc_mod_input_template.py)



