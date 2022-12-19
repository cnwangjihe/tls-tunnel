import os
import logging
import coloredlogs
import argparse
import tomli
import global_var

from threading import Thread

from utils import load_ECDSA_pubkey
from server import TunnelServer
from client import TunnelClient

CONF_DIR = "./conf.d"

def main():
    coloredlogs.install(level="DEBUG")

    parser = argparse.ArgumentParser(description="A TCP forwarder with Transport Layer Security")

    parser.add_argument("-c", "--conf", metavar="CONFIG_FILE", type=str, required=True, help="toml config file path")

    args = parser.parse_args()
    conf_path: str = args.conf
    with open(conf_path, "r") as f:
        config = tomli.loads(f.read())

    assert "global" in config
    assert "ca_url" in config["global"]
    assert "ca_pubkey" in config["global"]
    
    os.chdir(os.path.dirname(conf_path))

    with open(config["global"]["ca_pubkey"], "r") as f:
        global_var.ca_pubkey = load_ECDSA_pubkey(f.read())
    global_var.ca_url = config["global"]["ca_url"]

    # cd to config file dir

    logging.info("main module staring...")

    threads: list[Thread] = []
    for i in config["tunnels"]:
        v = config["tunnels"][i]
        if v["mode"] == 0:
            threads.append(TunnelServer(v))
        elif v["mode"] == 1:
            threads.append(TunnelClient(v))
        else:
            raise NotImplementedError
        threads[-1].start()


if __name__ == "__main__":
    main()