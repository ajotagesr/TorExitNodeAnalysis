#!/bin/bash

# Define the scripts to run
SCRIPT1="sudo python3 update_ipmasks.py tor"
SCRIPT2="sudo python3 update_ipmasks.py sblam"
SCRIPT3="sudo python3 update_ipmasks.py cleantalk_new_1d"
SCRIPT4="sudo python3 update_ipmasks.py myip"
SCRIPT5="sudo python3 update_ipmasks.py bruteforceblocker"

sudo update-ipsets run bds_atif bitcoin_nodes blocklist_de blocklist_de_apache blocklist_de_bots blocklist_de_bruteforce blocklist_de_ftp blocklist_de_imap blocklist_de_mail blocklist_de_sip blocklist_de_ssh blocklist_de_strongips blocklist_net_ua botscout botvrij_dst botvrij_src bruteforceblocker ciarmy cleantalk_new cleantalk_new_1d cleantalk_updated cleantalk_top20 cleantalk cleantalk_1d cleantalk_7d cleantalk_30d cybercrime dataplane_dnsrd dataplane_sipinvitation dataplane_sipquery dataplane_sipregistration dataplane_sshclient dataplane_sshpwauth dataplane_vncrfb dm_tor et_compromised et_dshield et_tor fullbogons gpf_comics greensnow iblocklist_ads iblocklist_ciarmy_malicious iblocklist_edu iblocklist_level2 iblocklist_level3 iblocklist_spyware myip php_commenters php_dictionary php_harvesters php_spammers sblam socks_proxy spamhaus_drop sslproxies stopforumspam tor_exits vxvault yoyo_adservers

# replace with the path to code
cd $PATH_TO_CODE


# delete repository if it already exists
if [ -d "blocklist-ipsets" ]; then
    sudo rm -rf blocklist-ipsets
fi

# clonar repo
git clone https://github.com/firehol/blocklist-ipsets.git

# replace with path to the folder where your virtual env is
# or delete if it doesn't apply to your case
cd $PATH_TO_CODE
source venv/bin/activate
cd src

# Launch first script
$SCRIPT1 &
PID1=$!
sleep 120

# Launch second script
$SCRIPT2 &
PID2=$!
sleep 120

# Launch third script
$SCRIPT3 &
PID3=$!
sleep 120

# Launch fourth script
$SCRIPT4 &
PID4=$!
sleep 120

# Launch fifth script
$SCRIPT5 &
PID5=$!
sleep 120

# delete if no virtual env was used
deactivate
