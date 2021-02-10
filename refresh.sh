pwd
echo ========== Running ucc-gen   ===========
ucc-gen
echo
echo
echo ========== Copying the output directory into the Docker container ===========
docker cp ./output/Splunk_TA_New_Relic/ splunk_ucc:/opt/splunk/etc/apps/Splunk_TA_New_Relic
echo  ========  restarting Splunk =========
docker exec -u root splunk_ucc /opt/splunk/bin/splunk restart


