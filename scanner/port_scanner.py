import socket

def scan_ports(host):
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,3306,8080]

    open_ports = []

    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, port))
            open_ports.append(port)
            s.close()
        except:
            continue

    if open_ports:
        return "Open Ports: " + ", ".join(map(str, open_ports))
    return "No common ports open"