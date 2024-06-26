#!/bin/bash

print_control_preamble () {
    echo $1
}
if [ -z $1 ]; then 
    echo "Enter target csv"
    exit 
fi
#Grab every control ID that needs to be iterated from target file
ALL_CONTROL_ID=$(cat $1 | egrep -o "ESXI-\d{2}-\d{6}")

#Grab every host ID that needs to be iterated over in target file
#Future pattern will need to be capable of grabbing the first column, as the names
#will be wildly different in future. Easiest solution is to start with an anchor
#followed by a negative lookahead for a coma, then some text not equaling the row
#category names, ending with a comma
ALL_HOST_ID=$(cat $1 | egrep -o "apcmv1-c1-esxi\d{2}\.apc\.ntrs\.com")
for HOST_ID in $ALL_HOST_ID; do echo $HOST_ID; done

cat testcsv.csv | ggrep -Po "(?<=Expected Result,(Site\sSpecific,){4}).*" 
#ALL_EXPECTED_RESULTS=$(cat $1 | egrep -o "apcmv1-c1-esxi\d{2}\.apc\.ntrs\.com")

for CONTROL_ID in $ALL_CONTROL_ID; do
    echo "Done"
    #print_control_preamble $CONTROL_ID;
done

#Primary loop on control ID
#Write preamble block with control ID, ending at results
#Secondary loop on host ID
#Check host control value against expected value for that control ID
#Write passed or failed based on check with rest of result template

