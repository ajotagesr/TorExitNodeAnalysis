# Info + setup

## Info

> The `.pkl` and `.log` files contain info from 01/04/2025 to 07/07/2025, not just until 01/06/2025 as in the article.


## Setup

1. Install the `update-ipsets.sh` script from the [FireHOL project](https://github.com/firehol/blocklist-ipsets/).

2. Install the required Python packages (the use of a virtual environment is recommended):
```bash
pip install -r requirements.txt
```

1. Substitute any absolute paths in the `update_ipsets.sh` and `update_ipmasks.py` scripts (in the `code` folder of this repository) with the paths you will use.

2. Before running the script, create the empty `.log` files with the correct names.

3. Use a cron job to run the script (the `update_ipsets.sh` script in this repo, not the one from the FireHOL project) periodically.

