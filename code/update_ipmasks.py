import ipaddress
import os
import time
import pickle
import sys
from logger import Logger

BLOCKLISTS = [
    "bds_atif.ipset", "bitcoin_nodes.ipset", "blocklist_de.ipset", "blocklist_de_apache.ipset", "blocklist_de_bots.ipset", "blocklist_de_bruteforce.ipset", "blocklist_de_ftp.ipset", "blocklist_de_imap.ipset", "blocklist_de_mail.ipset", "blocklist_de_sip.ipset", "blocklist_de_ssh.ipset", "blocklist_de_strongips.ipset", "blocklist_net_ua.ipset", "botscout_1d.ipset", "botvrij_dst.ipset", "botvrij_src.ipset", "bruteforceblocker.ipset", "ciarmy.ipset", "cleantalk_new_1d.ipset", "cleantalk_top20.ipset", "cleantalk_updated_1d.ipset", "cybercrime.ipset", "dataplane_dnsrd.ipset", "dataplane_sipinvitation.ipset", "dataplane_sipquery.ipset", "dataplane_sipregistration.ipset", "dataplane_sshclient.ipset", "dataplane_sshpwauth.ipset", "dataplane_vncrfb.ipset", "dm_tor.ipset", "et_compromised.ipset", "et_dshield.netset", "et_tor.ipset", "fullbogons.netset", "gpf_comics.ipset", "greensnow.ipset", "iblocklist_ads.netset", "iblocklist_ciarmy_malicious.netset", "iblocklist_edu.netset", "iblocklist_level2.netset", "iblocklist_level3.netset", "iblocklist_spyware.netset", "myip.ipset", "php_commenters.ipset", "php_dictionary.ipset", "php_harvesters.ipset", "php_spammers.ipset", "sblam.ipset", "socks_proxy.ipset", "spamhaus_drop.netset", "sslproxies.ipset", "stopforumspam.ipset", "tor_exits.ipset", "vxvault.ipset", "yoyo_adservers.ipset"
]

# "dronebl_anonymizers.ipset", "dronebl_auto_botnets.ipset", "dronebl_autorooting_worms.ipset", "dronebl_compromised.ipset", "dronebl_ddos_drones.ipset", "dronebl_dns_mx_on_irc.ipset", "dronebl_irc_drones.ipset", "dronebl_unknown.ipset", "dronebl_worms_bots.ipset", "stopforumspam.ipset", "stopforumspam_180d.ipset", "stopforumspam_1d.ipset", "stopforumspam_30d.ipset", "stopforumspam_365d.ipset", "stopforumspam_7d.ipset", "stopforumspam_90d.ipset",

GITHUB_BLOCKLISTS = [
    "bitcoin_nodes.ipset", "bitcoin_nodes_1d.ipset", "bitcoin_nodes_30d.ipset", "bitcoin_nodes_7d.ipset", "stopforumspam.ipset"
]

# replace with the path to your ipsets directory if different
IPSETS_DIR = "/etc/firehol/ipsets"

TOR_EXITS_FILE = os.path.join(IPSETS_DIR, "tor_exits.ipset")
TOR_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "tor_ipmasks.pkl")
TOR_LOG_FILE = os.path.join(os.path.dirname(__file__), "tor_ipmasks.log")

BLOCKLIST_DE_STRONGIPS_FILE = os.path.join(IPSETS_DIR, "blocklist_de_strongips.ipset")
BLOCKLIST_DE_STRONGIPS_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "blocklist_de_strongips_ipmasks.pkl")
BLOCKLIST_DE_STRONGIPS_LOG_FILE = os.path.join(os.path.dirname(__file__), "blocklist_de_strongips_ipmasks.log")

BRUTEFORCEBLOCKER_FILE = os.path.join(IPSETS_DIR, "bruteforceblocker.ipset")
BRUTEFORCEBLOCKER_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "bruteforceblocker_ipmasks.pkl")
BRUTEFORCEBLOCKER_LOG_FILE = os.path.join(os.path.dirname(__file__), "bruteforceblocker_ipmasks.log")

MYIP_FILE = os.path.join(IPSETS_DIR, "myip.ipset")
MYIP_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "myip_ipmasks.pkl")
MYIP_LOG_FILE = os.path.join(os.path.dirname(__file__), "myip_ipmasks.log")

CLEANTALK_NEW_1D_FILE = os.path.join(IPSETS_DIR, "cleantalk_new_1d.ipset")
CLEANTALK_NEW_1D_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "cleantalk_new_1d_ipmasks.pkl")
CLEANTALK_NEW_1D_LOG_FILE = os.path.join(os.path.dirname(__file__), "cleantalk_new_1d_ipmasks.log")

SBLAM_FILE = os.path.join(IPSETS_DIR, "sblam.ipset")
SBLAM_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "sblam_ipmasks.pkl")
SBLAM_LOG_FILE = os.path.join(os.path.dirname(__file__), "sblam_ipmasks.log")


logger = None
IPSET_FILE = None
IPMASKS_FILE = None
LOG_FILE = None

parameters_dict = {
    "tor": {
        "file": TOR_EXITS_FILE,
        "data_dict": TOR_IPMASKS_FILE,
        "log_file": TOR_LOG_FILE
    },
    "blocklist_de_strongips": {
        "file": BLOCKLIST_DE_STRONGIPS_FILE,
        "data_dict": BLOCKLIST_DE_STRONGIPS_IPMASKS_FILE,
        "log_file": BLOCKLIST_DE_STRONGIPS_LOG_FILE
    },
    "bruteforceblocker": {
        "file": BRUTEFORCEBLOCKER_FILE,
        "data_dict": BRUTEFORCEBLOCKER_IPMASKS_FILE,
        "log_file": BRUTEFORCEBLOCKER_LOG_FILE
    },
    "myip": {
        "file": MYIP_FILE,
        "data_dict": MYIP_IPMASKS_FILE,
        "log_file": MYIP_LOG_FILE
    },
    "cleantalk_new_1d": {
        "file": CLEANTALK_NEW_1D_FILE,
        "data_dict": CLEANTALK_NEW_1D_IPMASKS_FILE,
        "log_file": CLEANTALK_NEW_1D_LOG_FILE
    },
    "sblam": {
        "file": SBLAM_FILE,
        "data_dict": SBLAM_IPMASKS_FILE,
        "log_file": SBLAM_LOG_FILE
    },
}


def set_parameters(name):
    IPSET_FILE = parameters_dict[name]["file"]
    IPMASKS_FILE = parameters_dict[name]["data_dict"]
    LOG_FILE = parameters_dict[name]["log_file"]
    logger = Logger(LOG_FILE)
    return IPSET_FILE, IPMASKS_FILE, logger


def handle_github_blocklists():
    for filename in GITHUB_BLOCKLISTS:
        if os.path.exists(f"/etc/firehol/ipsets/{filename}"):
            os.system(f"sudo rm /etc/firehol/ipsets/{filename}")
            logger.info("handle_github_blocklists", f"Removed previous {filename} from /etc/firehol/ipsets/")
        if os.path.exists(f"blocklist-ipsets/{filename}"):
            os.system(f"sudo mv blocklist-ipsets/{filename} /etc/firehol/ipsets/")
            logger.info("handle_github_blocklists", f"Moved {filename} to /etc/firehol/ipsets/")
        else:
            logger.warning("handle_github_blocklists", f"Could not find {filename} in /etc/firehol/ipsets/ or blocklist-ipsets/")
            sys.exit(1)


# get the list of files in the directory
def get_file_list():
    file_list = os.listdir(IPSETS_DIR)
    # filter out files
    file_list = [f for f in file_list if f in BLOCKLISTS]
    #print(BLOCKLISTS)
    #print("*"*30)

    if len(file_list) == 0:
        logger.error("get_file_list", "No blocklist files found")
        sys.exit(1)
    elif len(file_list) != 55:
        logger.warning("get_file_list", f"Incorrect number of blocklist files: {len(file_list)}")
    else:
        logger.info("get_file_list", "correct number of blocklist files found")

    file_list.sort()
    #print (file_list)

    return file_list


# get the list of IP addresses from a file
def get_ips_from_file(filename):
    content = []
    if not os.path.exists(os.path.join(IPSETS_DIR, filename)):
        return content
    with open(os.path.join(IPSETS_DIR, filename), 'r') as f:
        content = f.read()
    ip_addresses = [line.strip() for line in content.split("\n") if not line.startswith("#")][:-1]
    return ip_addresses


# build the dictionary of IP addresses from the blocklists
def read_blocklists(file_list):
    ip_dict = {}
    for filename in file_list:
        ip_dict[filename] = set(get_ips_from_file(filename))
        # print(filename, ": ", len(ip_dict[filename]))
    return ip_dict


##############################################################
##############################################################
##############################################################
def create_db(filename):
    data_dict = {
        "dates": [],
        "ipmasks": {},
        "ip_total_number": [],
        "ip_today_number": [],
        "ips_per_blocklist": {
            str(bl): [] for bl in BLOCKLISTS
        }
    }
    if not os.path.exists(filename):
        with open(filename, 'wb') as f:
            pickle.dump(data_dict, f)
            logger.info("create_db", f"Created file {filename}")
    return data_dict


##############################################################
##############################################################
##############################################################
def get_ipmasks(mask_file):
    try:
        with open(mask_file, 'rb') as f:
            ipmasks = pickle.load(f)
            logger.info("get_ipmasks", f"Loaded masks from {mask_file}")
        return ipmasks
    except:
        logger.error("get_ipmasks", f"Could not open file {mask_file}")
        return {
            "dates": [],  # list of dates
            "ipmasks": {},  # dictionary of IP addresses and their masks
            "ip_total_number": [],  # number of IPs recorded in total
            "ip_today_number": [],  # number of IPs in this blocklist today
            "ips_per_blocklist": {
                str(bl): [] for bl in BLOCKLISTS
            }  # number of IPs per blocklist
        }


##############################################################
##############################################################
##############################################################
def update_ipmasks(data_dict, ips, ip_dict, masks_file):
    current_date = time.time()
    masks = []

    date_list = data_dict["dates"]
    ipmasks = data_dict["ipmasks"]
    # get the list of IP addresses for which masks have been built
    ip_list = list(ipmasks.keys())
    # add the current date to the list of dates
    data_dict["dates"].append(current_date)
    date_index = len(data_dict["dates"]) - 1
    data_dict["ip_today_number"].append(len(ips))

    # if it is the first time the script is run, we can just build the masks for current IPs
    if len(ip_list) == 0:
        logger.info("update_ipmasks", f"Building {len(ips)} masks for {masks_file}")
        masks = build_masks(ips, ip_dict)
    # take into account some IPs may have "disappeared", still need to build masks for them (?)
    else:
        ips_union = list(set(ips) | set(ip_list))
        ips = ips_union
        logger.info("update_ipmasks", f"Building {len(ips)} masks for {masks_file}")
        masks = build_masks(ips, ip_dict)

    data_dict["ip_total_number"].append(len(ips))

    # for each ip address, update the masks
    for ip in ips:
        if ip not in ipmasks:
            ipmasks[ip] = {"masks": [], "first_seen": date_index}
        ipmasks[ip]["masks"].append(masks[ips.index(ip)])

    logger.info("update_ipmasks", f"Updated {len(ips)} masks in {masks_file}")

    data_dict["ipmasks"] = ipmasks

    # update the masks file
    with open(masks_file, 'wb') as f:
        pickle.dump(data_dict, f)

    return data_dict



##############################################################
##############################################################
##############################################################
def ip_in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


##############################################################
##############################################################
##############################################################
def build_masks(ips, ip_dict):
    data = []
    total = len(ips)
    update_interval = max(1, total // 100)  # Update every 1% of progress

    for i, ip in enumerate(ips, start=1):
        mask_bits = ""
        for k, v in ip_dict.items():
            if k.endswith(".ipset"):
                mask_bits += "1" if ip in v else "0"
            else:
                # check if the IP is in the list
                if ip in v:
                    mask_bits += "1"
                else:  # check if the IP is in any of the networks
                    try:
                        mask_bits += "1" if any(map(lambda net: ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False), [el for el in v if "/" in el])) else "0"
                    except ValueError:
                        mask_bits += "0"


        mask_bits = "".join(mask_bits).ljust(56, "0")  # Pad to 56 bits
        data.append(int(mask_bits, 2).to_bytes(7, byteorder='big'))

        if i % update_interval == 0 or i == total:
            print(f"{i}/{total} IPs", end="\r")

    print()
    return data


##############################################################
##############################################################
##############################################################
def update_ips_per_blocklist(data_dict, file_list):
    ips_per_blocklist = {}
    i = 0

    while i in range(len(file_list)):
        ips_per_blocklist[file_list[i]] = 0
        i += 1

    for _, v in data_dict["ipmasks"].items():
        # get the latest mask for each IP
        mask = v["masks"][-1]

        string_mask = bin(int.from_bytes(mask, byteorder='big'))[2:].zfill(56)
        # for each "1" in the mask, increment the corresponding blocklist counter
        for i in range(len(string_mask)):
            if string_mask[i] == "1":
                ips_per_blocklist[file_list[i]] += 1
    
    if "ips_per_blocklist" not in data_dict:
        data_dict["ips_per_blocklist"] = {str(bl): [] for bl in BLOCKLISTS}
    
    for k, v in ips_per_blocklist.items():
        data_dict["ips_per_blocklist"][k].append(v)

    # update the masks file
    with open(IPMASKS_FILE, 'wb') as f:
        pickle.dump(data_dict, f)

    return data_dict["ips_per_blocklist"]


##############################################################
##############################################################
##############################################################
def get_recorded_dates(data_dict):
    return data_dict["dates"]


##############################################################
##############################################################
##############################################################
if __name__ == "__main__":
    # script should be run with the name of the blocklist as argument
    if len(sys.argv) != 2:
        print("Usage: python update_ipmasks.py <blocklist_name>")
        sys.exit(1)

    if sys.argv[1] not in parameters_dict:
        print(f"Blocklist name should be one of: {', '.join(parameters_dict.keys())}")
        sys.exit(1)

    IPSET_FILE, IPMASKS_FILE, logger = set_parameters(sys.argv[1])

    logger = Logger(LOG_FILE)

    logger.separator()
    logger.info("update_ipmasks", f"Starting update_ipmasks.py script for {sys.argv[1]}")  # TODO change

    ip_dict = {}
    ips = []
    data_dict = {}

    if sys.argv[1] == "tor":
        handle_github_blocklists()

    # get the list of files
    file_list = get_file_list()

    # read all blocklists
    ip_dict = read_blocklists(file_list)

    # get the current list of ips we want to build masks for
    ips = get_ips_from_file(IPSET_FILE)


    # read mask files
    if not os.path.exists(IPMASKS_FILE):
        data_dict = create_db(IPMASKS_FILE)
    else:
        data_dict = get_ipmasks(IPMASKS_FILE)

    # update mask files
    update_ipmasks(data_dict, ips, ip_dict, IPMASKS_FILE)  # TODO!
    update_ips_per_blocklist(data_dict, file_list)

    logger.info("update_ipmasks", f"Updated mask file")

    ##############################################################
    ##############################################################
    ##############################################################

    logger.info("update_ipmasks", "Finished update_ipmasks.py script")
    logger.separator()

