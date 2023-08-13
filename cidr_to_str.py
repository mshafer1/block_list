"""Utility cli to conver IP cidr notation to network-broadcast and print."""
import sys

import ip_calc


def main(argv=None):
    """Print out network-broadcast for argv[0] given in IP/cidr."""
    if argv is None:
        argv = sys.argv[1:]

    value = argv[0]

    ip = ip_calc.IP.from_cidr(value)

    print(f"{ip.network.as_string()}-{ip.broadcast.as_string()}")


if __name__ == "__main__":
    main()
