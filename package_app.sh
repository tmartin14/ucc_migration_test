#! /bin/bash
#    usage:    ./ hckage_app.sh TA_directory 

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
    echo "   Usage:   ${0} TA_Directory"
    echo
    exit 9999 # die with error code 9999
fi


#remove any traiing / from the dir name
AOB_TA_DIR=${AOB_TA_DIR%/}
cd ./output
# Ensure file permissions are set correctly
find ${AOB_TA_DIR} -type d -exec chmod 755 {} \;
find ${AOB_TA_DIR} -type f -exec chmod 644 {} \;
# Package the app
COPYFILE_DISABLE=1 tar -czf ./${AOB_TA_DIR}.tgz ${AOB_TA_DIR}
cd ../

#tar -cv --exclude='*DS_Store' not_multi_root > not_multi_root.tar