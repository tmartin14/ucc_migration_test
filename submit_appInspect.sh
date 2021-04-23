#!/bin/bash 

# Create your packaged app file using the following command:
#      COPYFILE_DISABLE=1 tar -cvzf <appname>.tar.gz <appname_directory>


# ----------------------------------------------------
#                Check the inputs
# ----------------------------------------------------
# Did the user specify the file to submit?   If not , get it now
if [ $# -eq 0 ]; then
    read -p 'Enter the full path to the filename of the Splunk app to submit: ' APP_FILE_PATH 
  else
    APP_FILE_PATH="$1"
fi

### Check if the file exists, if not, exit ###
if [ ! -f "$APP_FILE_PATH" ]; then
    echo "ERROR:    $APP_FILE_PATH does not exist."
    echo
    echo "   Usage: ${0} <TA_Directory>"
    echo
    exit 9999 # die with error code 9999
fi


# ----------------------------------------------------
#                Main processing loop
# ----------------------------------------------------
main() {
     echo
     # ----------------------------------------------------
     # Login to Splunkbase & get a token
     # ----------------------------------------------------
     read -p    'Enter your Splunkbase login: ' SPLUNKBASE_USER
     read -s -p 'Enter your Splunkbase password: ' SPLUNKBASE_PASSWORD
     echo
     AUTH_TOKEN=$(echo -n "$SPLUNKBASE_USER:$SPLUNKBASE_PASSWORD" | base64)

     RESPONSE=`curl -s -X GET --header "Authorization: Basic $AUTH_TOKEN"  --url "https://api.splunk.com/2.0/rest/login/splunk" `
     STATUS_CODE=`echo $RESPONSE | jq -r '.status_code'`
     if [ $STATUS_CODE -ne 200 ]; then 
          echo $RESPONSE | jq -r '.msg' 
          exit 
     fi
     log "Successfully Athenticated..."
     echo
     TOKEN=`echo $RESPONSE | jq -r '.data.token' `

     # ----------------------------------------------------
     # submit the application for appInspect
     # ----------------------------------------------------
     log "Submitting AppInspect request with Splunk Cloud compliance..."
     RESPONSE=`curl -s -X POST  --connect-timeout 20 --max-time 120 \
          -H "Authorization: bearer $TOKEN" \
          -H "Cache-Control: no-cache" \
          -F "app_package=@\"$APP_FILE_PATH\"" \
          -F "included_tags=cloud" \
          --url "https://appinspect.splunk.com/v1/app/validate" `
     RESULT=$?

     if test "$RESULT" != "0"; then     
          log "ERROR: Submission failed with: $RESULT   (28 = connection timed out)"
          log "$RESPONSE"
          if test "$RESULT" == 28; then
            log "Please rety this submission again using ${0} $APP_FILE_PATH"
          fi
          exit
     fi
     
     REQUEST_ID=`echo "$RESPONSE" | jq -r '.request_id' `
     log "request_id=$REQUEST_ID"

     # wait for the report to be ready
     log "Waiting for appInspect request to complete... (this could take several minutes, checking status every 60 seconds)"
     while ! check_status "$REQUEST_ID"; do
          sleep 60
     done
     echo "$RESPONSE"

     # get the report results  
     get_results "$REQUEST_ID" "appInspect_results.html"
     echo 
     log "Done."
     echo
}




# ----------------------------------------------------
#               Utlility Functions
# ----------------------------------------------------
log(){
     { date; echo "   $1"; } | tr "\n" " "
     echo
}

# Retrieve the status of the a submission
# check_status(<request_id>)
check_status(){
     RESPONSE=`curl -s -X GET \
         -H "Authorization: bearer $TOKEN" \
         --url "https://appinspect.splunk.com/v1/app/validate/status/$1" `
     RESULT=$?
     #echo "$RESPONSE"

     if test "$RESULT" != "0"; then     
          log "ERROR: $RESPONSE"
          exit
     fi

     { echo "   "; date; echo "   status ="; echo "$RESPONSE" | jq -r .status; } | tr "\n" " "
     #echo "$RESPONSE"
     echo
     return `echo $RESPONSE | jq -r .status | grep -q 'SUCCESS\|FAILURE\|FAILED' `
}

# Retrieve report results  for a submission
# get_results(<request_id> <output_filename>) 
get_results(){
     log "Retrieving Report..."
     curl -s -X GET \
          -H "Authorization: bearer $TOKEN" \
          -H "Cache-Control: no-cache" \
          -H "Content-Type: text/html" \
         --url "https://appinspect.splunk.com/v1/app/report/$1" > "$2"
     open "$2"
}

#  call the main function to process the request
main
