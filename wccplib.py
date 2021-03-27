import struct

WCCP2_HERE_I_AM = struct.pack("!I", 10)
WCCP2_I_SEE_YOU = struct.pack("!I", 11)
WCCP2_REDIRECT_ASSIGN = struct.pack("!I", 12)
WCCP2_REMOVAL_QUERY = struct.pack("!I", 13)
WCCP2_VERSION = struct.pack("!H", 0x200)
WCCP2_SECURITY_INFO = struct.pack("!H", 0)
WCCP2_NO_SECURITY = struct.pack("!I", 0)
WCCP2_SERVICE_INFO = struct.pack("!H", 1)
WCCP2_SERVICE_STANDARD = struct.pack("!B", 0)
WCCP2_WC_ID_INFO = struct.pack("!H", 3)
WCCP2_WC_VIEW_INFO = struct.pack("!H", 5)
WCCP2_REDIRECT_ASSIGN2 = struct.pack("!H", 6)
WCCP2_ROUTER_ID_INFO = struct.pack("!H", 2)
WCCP2_ROUTER_VIEW_INFO = struct.pack("!H", 4)


class ip_address:
    def string2bytes(self, ip):
        octet_list = ip.strip().split('.')
        byte_string = b"".join([struct.pack("!B", int(i)) for i in octet_list])
        return byte_string

    def __init__(self, ip):
        self.ip = self.string2bytes(ip)

    def get_ip(self):
        return self.ip

    def bytes2string(self):
        ip_string = ""
        ip_string += str(struct.unpack_from("!B", self.ip, offset=0)[0])
        ip_string += "."
        ip_string += str(struct.unpack_from("!B", self.ip, offset=1)[0])
        ip_string += "."
        ip_string += str(struct.unpack_from("!B", self.ip, offset=2)[0])
        ip_string += "."
        ip_string += str(struct.unpack_from("!B", self.ip, offset=3)[0])
        return ip_string

    def int2bytes(self, ip):
        return struct.pack(">I", ip)

    def next(self):
        ip_int = int(self.ip.encode("hex"), 16)
        ip_int = ip_int + 1
        self.ip = self.int2bytes(ip_int)
        return self

    def __cmp__(self, other):

        ip_int = int(self.ip.encode("hex"), 16)
        other_int = int(other.get_ip().encode("hex"), 16)

        if ip_int < other_int:
            return -1
        elif ip_int == other_int:
            return 0
        else:
            return 1


def get_my_wan_address():
    raise NotImplementedError


class wccp_web_cache_view_info_component:
    def __init__(self, rip, ip, last_isy):
        self.type = WCCP2_WC_VIEW_INFO
        self.change = struct.pack("!I", 1) 
        self.nRouter = struct.pack("!I", 1) 
        self.router_list = []
        if last_isy != None:
            self.router_list.append(last_isy.router_ip.get_ip())
        else:
            self.router_list.append(rip.get_ip())
        if last_isy != None:
            self.rID = struct.pack("!I", last_isy.recv_id)
        else:
            self.rID = struct.pack("!I", 0xFFFFFFFF)
        self.nCaches = struct.pack("!I", 1)
        self.cache = ip_address(ip).get_ip()
        data = b"".join([
            self.change,
            self.nRouter,
            b"".join(self.router_list),
            self.rID,
            self.nCaches,
            self.cache
        ])
        length = len(data)
        self.length = struct.pack("!H", length)
        self.data = b"".join([self.type, self.length, data])
    
    def get_data(self):
        return self.data

    @staticmethod
    def get_zmap_template():
        type = WCCP2_WC_VIEW_INFO
        change = struct.pack("!I", 1) 
        nRouter = struct.pack("!I", 1) 
        router_list = []
        router_list.append(b"${DADDR_N}")
        rID = struct.pack("!I", 0xFFFFFFFF)
        nCaches = struct.pack("!I", 1)
        cache = b"${SADDR_N}"
        data = b"".join([
            change,
            nRouter,
            b"".join(router_list),
            rID,
            nCaches,
            cache
        ])
        length = len(data) - len("${XADDR_N}")*2 + 8
        length = struct.pack("!H", length)
        return b"".join([type, length, data])


class wccp_web_cache_identity_info_component:
    def __init__(self, ip):
        self.type = WCCP2_WC_ID_INFO
        self.identity_element = ip_address(ip).get_ip()
        self.rht = struct.pack("!I", 0) + struct.pack("!I",0xFFFFFFFF)*8
        self.rht += struct.pack("!H", 10000)
        self.rht += struct.pack("!H", 0)
        data = b"".join([
            self.identity_element,
            self.rht,
        ])
        length = len(data)
        self.length = struct.pack("!H", length)
        self.data = b"".join([self.type, self.length, data])
    
    def get_data(self):
        return self.data

    @staticmethod
    def get_zmap_template():
        type = WCCP2_WC_ID_INFO
        rht = struct.pack("!I", 0) + struct.pack("!I", 0xFFFFFFFF)*8
        rht += struct.pack("!H", 10000)
        rht += struct.pack("!H", 0)
        data = b"".join([
            b"${SADDR_N}",
            rht
        ])
        length = len(data) - 9 + 4 - 1
        length = struct.pack("!H", length)
        return b"".join([type, length, data])


class wccp_service_info_component:
    def __init__(self):
        self.type = WCCP2_SERVICE_INFO
        self.service_type = WCCP2_SERVICE_STANDARD
        self.service_id = struct.pack("!B", 0)
        self.priority = struct.pack("!B", 0)
        self.protocol = struct.pack("!B", 0)
        self.service_flags = struct.pack("!I",0)
        self.ports = []
        for i in range(0,8):
                self.ports.append(struct.pack("!H", 0))

        data = b"".join([
            self.service_type,
            self.service_id,
            self.priority,
            self.protocol,
            self.service_flags,
            b"".join(self.ports)
        ])
        length = len(data)
        self.length = struct.pack("!H", length)
        self.data = b"".join([self.type, self.length, data])
    
    def get_data(self):
        return self.data


class wccp_security_component:
    def __init__(self):
        self.type = WCCP2_SECURITY_INFO
        self.option = WCCP2_NO_SECURITY

        data = b"".join([
            self.option
        ])
        length = len(data)
        self.length = struct.pack("!H", length)
        self.data = b"".join([self.type, self.length, data])

    def get_data(self):
        return self.data


class wccp_hia_header:
    def __init__(self, message):
        self.type = WCCP2_HERE_I_AM
        self.version = WCCP2_VERSION
        data = message
        if b"${SADDR_N}" in data:
            length = len(data) - len("${SADDR_N}") - len("${DADDR_N}") - len("${SADDR_N}") + 12
        else:
            length = len(data)
        self.length = struct.pack("!H", length)
        self.data = b"".join([self.type, self.version, self.length, data])
    
    def get_data(self):
        return self.data
            

class wccp_hia_message:
    def __init__(self, rip, ip, last_isy):
        self.security = wccp_security_component()
        self.service_info = wccp_service_info_component()
        self.identity_info = wccp_web_cache_identity_info_component(ip)
        self.view_info = wccp_web_cache_view_info_component(rip, ip, last_isy)
    
    def get_message(self):
        msg = b"".join([
            self.security.get_data(),
            self.service_info.get_data(),
            self.identity_info.get_data(),
            self.view_info.get_data()
        ])

        return wccp_hia_header(msg).get_data()

    @staticmethod
    def get_zmap_template():
        msg = b"".join([
            wccp_security_component().get_data(),
            wccp_service_info_component().get_data(),
            wccp_web_cache_identity_info_component.get_zmap_template(),
            wccp_web_cache_view_info_component.get_zmap_template()
        ])
        return wccp_hia_header(msg).get_data()


class wccp_assignment_info_component:
    '''
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |              Type             |          Length               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Assignment Key                        |
       |                               .                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Number of Routers                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Router Assignment Element 0                |
       |                              .                                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              .                                |
       |                              .                                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Router Assignment Element n                |
       |                              .                                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Number of Web-Caches                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Web-Cache 0                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              .                                |
       |                              .                                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Web-Cache n                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Bucket 0   |  Bucket 1     |   Bucket 2    |   Bucket 3    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                               .                               |
       |                               .                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Bucket 252 |  Bucket 253   |   Bucket 254  |   Bucket 255  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    This element identifies a particular assignment.

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Key IP Address                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Key Change Number                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Key IP Address

          Designated web-cache IP address

       Key Change Number

          Incremented if a change has occurred.

    '''
    def __init__(self, ip, isy_msg):
        self.type = WCCP2_REDIRECT_ASSIGN2
        self.key_ip = ip_address(ip).get_ip()
        self.key_change_number = struct.pack("!I", 0xFFFFFFFF)
        self.nrouters = struct.pack("!I", 1)
        self.router_ip = isy_msg.router_ip.get_ip()
        self.recv_id = struct.pack("!I", isy_msg.recv_id)
        self.change_num = struct.pack("!I", isy_msg.member_change_number)
        self.nservers = struct.pack("!I",1)
        self.server_ip = ip_address(ip).get_ip()
        self.bucket = b"".join([struct.pack("!B", 0x0) for _ in range(0,256)])

        data = b"".join([
            self.key_ip,
            self.key_change_number,
            self.nrouters,
            self.router_ip,
            self.recv_id,
            self.change_num,
            self.nservers,
            self.server_ip,
            self.bucket
        ])
        length = len(data)
        self.length = struct.pack("!H", length)
        self.data = b"".join([self.type, self.length, data])
    
    def get_data(self):
        return self.data


class wccp_ra_header:
    def __init__(self, message):
        self.type = WCCP2_REDIRECT_ASSIGN
        self.version = WCCP2_VERSION
        data = message
        length = len(data)
        self.length = struct.pack("!H",length)
        self.data = b"".join([self.type, self.version, self.length, data])
   
    def get_data(self):
        return self.data


class wccp_ra_message:
    def __init__(self, ip, isy_msg):
        self.security = wccp_security_component()
        self.service_info = wccp_service_info_component()
        self.assignment_info = wccp_assignment_info_component(ip, isy_msg)

    def get_message(self):
        msg = b"".join([
            self.security.get_data(),
            self.service_info.get_data(),
            self.assignment_info.get_data()
        ])

        return wccp_ra_header(msg).get_data()


class wccp_isy_message:
    def __init__(self, msg):
        offset = 0
        result = struct.unpack_from("!I", msg, offset=offset)[0]
        self.type = struct.pack("!I", result)

        if self.type != WCCP2_I_SEE_YOU:
            raise ValueError("Wrong header type")

        msg = msg[4:]
        self.version = struct.unpack_from("!H", msg, offset=offset)[0]

        if self.version != 0x200:
            raise ValueError("Wrong version %d" % (self.version))

        msg = msg[2:]

        self.length = struct.unpack_from("!H", msg, offset=offset)[0]

        msg = msg[2:]
        
        if self.length != len(msg):
            raise ValueError("Header length mismatch")

        if struct.unpack_from("!H", msg, offset=offset)[0] != 0x0:
            raise ValueError( "wrong security type")
        
        msg = msg[2:]
        
        if struct.unpack_from("!H", msg, offset=offset)[0] != 0x4:
            raise NotImplemented
        msg = msg[2:]

        if struct.unpack_from("!I", msg, offset=offset)[0] != 0x0:
            raise NotImplemented
        msg = msg[4:]

        if struct.unpack_from("!H", msg, offset=offset)[0] != 0x1:
            raise ValueError("Service info type wrong")
        
        msg = msg[2:]

        skip_length = struct.unpack_from("!H", msg, offset=offset)[0]
        msg = msg[2:]
        msg = msg[skip_length:]

        if struct.unpack_from("!H", msg, offset=offset)[0] != 0x2:
            raise ValueError("Router ID type wrong")
        msg = msg[2:]

        router_id_length = struct.unpack_from("!H", msg, offset=offset)[0]
        msg = msg[2:]

        nbytes = 4
        octets = []
        while nbytes > 0:
            curr_byte = struct.unpack_from("!B", msg, offset=offset)[0]
            octets.append(int(curr_byte))
            msg = msg[1:]
            nbytes -= 1
        router_id_length -= 4

        rip = ".".join([str(i) for i in octets])
        self.router_ip = ip_address(rip)

        self.recv_id = struct.unpack_from("!I", msg, offset=offset)[0]
        msg = msg[4:]
        router_id_length -= 4

        nbytes = 4
        octets = []
        while nbytes > 0:
            curr_byte = struct.unpack_from("!B", msg, offset=offset)[0]
            octets.append(int(curr_byte))
            msg = msg[1:]
            nbytes -= 1
        router_id_length -= 4

        rip = ".".join([str(i) for i in octets])
        self.server_ip = ip_address(rip)

        n_recv_from_addrs = struct.unpack_from("!I", msg, offset=offset)[0]
        msg = msg[4:]
        router_id_length -= 4

        if n_recv_from_addrs*4 != router_id_length:
            raise ValueError("router id length mismatch %d %d" % (n_recv_from_addrs*4, router_id_length))

        self.recv_from_addrs = []
        while n_recv_from_addrs > 0:
            nbytes = 4
            octets = []
            while nbytes > 0:
                curr_byte = struct.unpack_from("!B", msg, offset=offset)[0]
                octets.append(int(curr_byte))
                msg = msg[1:]
                nbytes -= 1
            router_id_length -= 4
            rip = ".".join([str(i) for i in octets])
            self.recv_from_addrs.append(ip_address(rip))
            n_recv_from_addrs -= 1

        if router_id_length != 0:
            raise ValueError("did not consume all router id elements")

        if struct.unpack_from("!H", msg, offset=offset)[0] != 0x4:
            raise ValueError("router view type wrong")

        msg = msg[2:]

        router_view_length = struct.unpack_from("!H", msg, offset=offset)[0]
        msg = msg[2:]

        self.member_change_number = struct.unpack_from("!I", msg, offset=offset)[0]
        msg = msg[4:]
        router_view_length -= 4

        nbytes = 4
        octets = []
        while nbytes > 0:
            curr_byte = struct.unpack_from("!B", msg, offset=offset)[0]
            octets.append(int(curr_byte))
            msg = msg[1:]
            nbytes -= 1
        router_view_length -= 4

        rip = ".".join([str(i) for i in octets])
        self.assignmet_key_addr = ip_address(rip)

        self.assignment_key_change_number = struct.unpack_from("!I", msg, offset=offset)[0]
        msg = msg[4:]
        router_view_length -= 4

        n_routers = struct.unpack_from("!I", msg, offset=offset)[0]
        msg = msg[4:]
        router_view_length -= 4


        self.router_addrs = []
        while n_routers > 0:
            nbytes = 4
            octets = []
            while nbytes > 0:
                curr_byte = struct.unpack_from("!B", msg, offset=offset)[0]
                octets.append(int(curr_byte))
                msg = msg[1:]
                nbytes -= 1
            router_view_length -= 4
            rip = ".".join([str(i) for i in octets])
            self.router_addrs.append(ip_address(rip))
            n_routers -= 1
       
        n_servers = struct.unpack_from("!I", msg, offset=offset)[0]
        msg = msg[4:]
        router_view_length -= 4

        if n_servers*44 != router_view_length:
            raise ValueError("router view length mismatch %d %d" % (n_servers*44, router_view_length))

        self.web_cache_info = msg