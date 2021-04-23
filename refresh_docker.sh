#! /bin/bash
#    usage:    ./refresh.sh TA_directory 

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
    echo "   Usage:    ./refresh.sh TA_Directory"
    echo
    exit 9999 # die with error code 9999
fi


#remove any traiing / from the dir name
AOB_TA_DIR=${AOB_TA_DIR%/}

pwd
echo
echo
echo ========== Delete the old TA from the container  ===========
echo "docker exec --user root splunk rm -rf /opt/splunk/etc/apps/${AOB_TA_DIR}"
docker exec --user root splunk rm -rf /opt/splunk/etc/apps/${AOB_TA_DIR}
echo ========== Copying the output directory into the Docker container ===========
echo "docker cp ./output/${AOB_TA_DIR}/ splunk:/opt/splunk/etc/apps/${AOB_TA_DIR}"
docker cp ./output/${AOB_TA_DIR}/ splunk:/opt/splunk/etc/apps/${AOB_TA_DIR}
echo  ========  restarting Splunk =========
echo "docker exec -u root splunk /opt/splunk/bin/splunk restart"
docker exec -u root splunk /opt/splunk/bin/splunk restart
echo
echo "Now login to Splunk and check your inputs.    If they don't load use this search"
echo "     index=_internal sourcetype=splunkd ERROR ModularInputs"
echo
date
