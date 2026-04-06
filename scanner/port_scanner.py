import socket

def scan_ports(host):

    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306]
    open_ports = []

    for port in common_ports:
        s = socket.socket()
        s.settimeout(1)

        try:
            s.connect((host, port))
            open_ports.append(port)
        except:
            pass

        s.close()

    return open_ports