import ipaddress


# function to convert CIDR to ip/netmask (OpenFlow matches)
def cidr_to_network_mask(cidr):
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return str(network.network_address), str(network.netmask)
    except Exception as e:
        return cidr, None

# function to map string to ip protocol number (for OpenFlow matches)
def get_ip_proto_num(proto_str):
    proto_map = {
        'icmp': 1,
        'tcp': 6,
        'udp': 17,
    }
    return proto_map.get(proto_str.lower()) 