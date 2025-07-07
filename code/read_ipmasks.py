import pickle
import os
import sys

TOR_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "tor_ipmasks.pkl")
SBLAM_IPMASKS_FILE = os.path.join(os.path.dirname(__file__), "sblam_ipmasks.pkl")
CLEANTALK_NEW_1D_FILE = os.path.join(os.path.dirname(__file__), "cleantalk_new_1d_ipmasks.pkl")
BRUTEFORCEBLOCKER_FILE = os.path.join(os.path.dirname(__file__), "bruteforceblocker_ipmasks.pkl")
MYIP_FILE = os.path.join(os.path.dirname(__file__), "myip_ipmasks.pkl")


mask_files = {
    "tor": TOR_IPMASKS_FILE,
    "sblam": SBLAM_IPMASKS_FILE,
    "cleantalk_new_1d": CLEANTALK_NEW_1D_FILE,
    "myip": MYIP_FILE,
    "bruteforceblocker": BRUTEFORCEBLOCKER_FILE
}



def get_data(filename):
    try:
        with open(filename, 'rb') as f:
            data_dict = pickle.load(f)
        return data_dict
    except FileNotFoundError:
        return {}


def get_dates(data_dict):
    return data_dict['dates']


def raw_print_data_dict(data_dict):
    print(data_dict)


def get_total_ips(data_dict):
    return data_dict["ip_total_number"]


def get_total_ips_per_date(data_dict):
    return data_dict["ip_today_number"]


def get_ips_per_blocklist(data_dict):
    return data_dict["ips_per_blocklist"]


def pretty_print_data_dict(data_dict):
    dates = []
    ips_dict = {}

    dates = data_dict['dates']
    print(dates)
    ips_dict = data_dict['ipmasks']

    for k, v in ips_dict.items():
        # bytes to string
        mask = v["masks"][-1]
        str_v = bin(int.from_bytes(mask, byteorder='big'))[2:].zfill(56)  
        print(k, " --> ", str_v)

    #print("Total IP masks: ", len(ips_dict))
    print()
    print("Total IPs: ", data_dict["ip_total_number"])
    print()
    print("IP numbers per date: ", data_dict["ip_today_number"])
    print()
    print("IPs per blocklist:")
    for k, v in data_dict["ips_per_blocklist"].items():
        print("     ", k, " --> ", v)
    print()
    print("Only the last mask is shown for each IP, for clarity.")
    print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python read_ipmasks.py blocklist_name")
        exit(0)

    blocklist_name = sys.argv[1]
    if blocklist_name not in mask_files:
        print("Invalid blocklist_name.")
        exit(0)

    filename = mask_files[blocklist_name]

    data_dict = get_data(filename)
    if data_dict == {}:
        print(f"File {filename} not found.")
        exit(0)
    #raw_print_data_dict(data_dict)
    pretty_print_data_dict(data_dict)
