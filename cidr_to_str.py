import sys

import ip_calc

def main(argv = None):
    if argv is None:
        argv = sys.argv[1:]
    
    value = argv[0]

    ip = ip_calc.IP.from_cidr(value)

    print(f"{ip.network.as_string()}-{ip.broadcast.as_string()}")

if __name__ == '__main__':
    main()
