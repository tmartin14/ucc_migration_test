pwd
echo ===========  removing output directory  ========
rm -rf output/
echo ========== Running ucc-gen   ===========
ucc-gen
echo
echo
echo   *******  TEMP FIX    *******
echo       copying the modinput_wrapper directory into the lib directory
cp -r ../addonfactory-ucc-library/splunktaucclib/modinput_wrapper ./output/Splunk_TA_New_Relic/lib/splunktaucclib
echo
echo   *****   once the pull request is merged adding modinput_wrapper to splunktaucclib we will NOT need this any more
echo       ******
echo
echo
echo ========== Delete the old TA from the container  ===========
docker exec --user root splunk_ucc rm -rf /opt/splunk/etc/apps/Splunk_TA_New_Relic
echo ========== Copying the output directory into the Docker container ===========
docker cp ./output/Splunk_TA_New_Relic/ splunk_ucc:/opt/splunk/etc/apps/Splunk_TA_New_Relic
echo  ========  restarting Splunk =========
docker exec -u root splunk_ucc /opt/splunk/bin/splunk restart
echo
date

