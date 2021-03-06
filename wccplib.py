import urllib2
import os
import struct
WCCP2_HERE_I_AM = "\x00\x00\x00\x0A"
WCCP2_I_SEE_YOU = "\x00\x00\x00\x0B"
WCCP2_REDIRECT_ASSIGN = "\x00\x00\x00\x0C"
WCCP2_REMOVAL_QUERY = "\x00\x00\x00\x0D"
WCCP2_VERSION = "\x02\x00"
WCCP2_SECURITY_INFO = "\x00\x00"
WCCP2_NO_SECURITY = "\x00\x00\x00\x00"
WCCP2_SERVICE_INFO = "\x00\x01"
WCCP2_SERVICE_STANDARD = "\x00"
WCCP2_WC_ID_INFO = "\x00\x03"
WCCP2_WC_VIEW_INFO = "\x00\x05"

class ip_address:
	def string2bytes(self,ip):
		octet_list = ip.split('.')
		byte_string = ""
		for octet in octet_list:
			octet = chr(int(octet))
			byte_string = byte_string + octet
		return byte_string
	def __init__(self,ip):
		self.ip = self.string2bytes(ip)
	def get_ip(self):
		return self.ip
    
        def bytes2string(self):
            ip_string = ""
            for octet in self.ip:
                int_octet = int(octet.encode("hex"), 16) 
                ip_string = ip_string + str(int_octet) + "."
            ip_string = ip_string.strip(".")
            return ip_string

        def int2bytes(self, ip):
            return struct.pack(">I",ip)

        def next(self):
            ip_int = int(self.ip.encode("hex"),16)
            ip_int = ip_int + 1
            self.ip = self.int2bytes(ip_int)
            return self
        
        def __cmp__(self, other):

            ip_int = int(self.ip.encode("hex"),16)
            other_int = int(other.get_ip().encode("hex"),16)

            if ip_int < other_int:
                return -1
            elif ip_int == other_int:
                return 0
            else:
                return 1

def get_my_wan_address():
	fqn = os.uname()[1]
    	ext_ip = urllib2.urlopen('http://icanhazip.com').read()
	return ext_ip.strip()

class wccp_web_cache_view_info_component:
	def __init__(self,rip,ip):
		self.type = WCCP2_WC_VIEW_INFO
		self.length = "\x00\x14"
		self.change = "\x00\x00\x00\x01"
		self.nRouter = "\x00\x00\x00\x01"
		self.router_list = []
		self.router_list.append(rip.get_ip())
		self.rID = "\x00\x00\x00\x00"
		self.nCaches = "\x00\x00\x00\x00"
		self.cache = ip_address(ip).get_ip()
	def get_type(self):
		return self.type
	def get_length(self):
		return self.length
	def get_change(self):
		return self.change
	def get_nrouter(self):
		return self.nRouter
	def get_router_list(self):
		return self.router_list
	def get_rid(self):
		return self.rID
	def get_ncache(self):
		return self.nCaches
	def get_cache(self):
		return self.cache
class wccp_web_cache_identity_info_component:
	def __init__(self, ip):
		self.type = WCCP2_WC_ID_INFO
		self.length = "\x00\x2C"
		self.identity_element = ip_address(ip).get_ip()
		self.rht = "\x00\x00\x00\x00"
		for i in range (0,32): self.rht = self.rht + "\x00"
		self.rht = self.rht + "\x27\x10"
		self.rht = self.rht + "\x00\x00" 
	def get_type(self):
		return self.type
	def get_length(self):
		return self.length
	def get_ip(self):
		return self.identity_element
	def get_rht(self):
		return self.rht

class wccp_service_info_component:
	def __init__(self):
		self.type = WCCP2_SERVICE_INFO
		self.length = "\x00\x18"
		self.service_type = WCCP2_SERVICE_STANDARD
		self.service_id = "\x00"
		self.priority = "\x00"
		self.protocol = "\x00"
		self.service_flags = "\x00\x00\x00\x00"
		self.ports = []
		for i in range(0,8):
			self.ports.append("\x00\x00")
	def get_type(self):
		return self.type
	def get_length(self):
		return self.length
	def get_service_type(self):
		return self.service_type
	def get_service_id(self):
		return self.service_id
	def get_priority(self):
		return self.priority
	def get_protocol(self):
		return self.protocol
	def get_service_flags(self):
		return self.service_flags
	def get_ports(self):
		return self.ports

class wccp_security_component:
	def __init__(self):
		self.type = WCCP2_SECURITY_INFO
		self.length = "\x00\x04"
		self.option = WCCP2_NO_SECURITY
	def get_type(self):
		return self.type
	def get_length(self):
		return self.length
	def get_option(self):
		return self.option

class wccp_header:
	def __init__(self):
		self.type = WCCP2_HERE_I_AM
		self.version = WCCP2_VERSION
		#8+28+24+24
		self.length = "\x00\x6C"
	def get_type(self):
		return self.type
	def get_version(self):
		return self.version
	def get_length(self):
		return self.length
	def set_length(self,length):
		self.length = length
class wccp_message:
	def __init__(self,rip,ip):
		self.header = wccp_header()
		self.security = wccp_security_component()
		self.service_info = wccp_service_info_component()
		self.identity_info = wccp_web_cache_identity_info_component(ip)
		self.view_info = wccp_web_cache_view_info_component(rip,ip)
	def get_message(self):
		byte_string = ""
		# WCCP Header
		byte_string = byte_string + self.header.get_type()
		byte_string = byte_string + self.header.get_version()
		byte_string = byte_string + self.header.get_length()
		
		# WCCP Security Info
		byte_string = byte_string + self.security.get_type()
		byte_string = byte_string + self.security.get_length()
		byte_string = byte_string + self.security.get_option()

		# WCCP Service Info
		byte_string = byte_string + self.service_info.get_type()
		byte_string = byte_string + self.service_info.get_length()
		byte_string = byte_string + self.service_info.get_service_type()
		byte_string = byte_string + self.service_info.get_service_id()
		byte_string = byte_string + self.service_info.get_priority()
		byte_string = byte_string + self.service_info.get_protocol()
		byte_string = byte_string + self.service_info.get_service_flags()
		for port in self.service_info.get_ports():
			byte_string = byte_string + port
		
		# WCCP Identity Info
	 	byte_string = byte_string + self.identity_info.get_type()
	 	byte_string = byte_string + self.identity_info.get_length()
	 	byte_string = byte_string + self.identity_info.get_ip()
	 	byte_string = byte_string + self.identity_info.get_rht()

		# WCCP View Info
	 	byte_string = byte_string + self.view_info.get_type()
	 	byte_string = byte_string + self.view_info.get_length()
	 	byte_string = byte_string + self.view_info.get_change()
	 	byte_string = byte_string + self.view_info.get_nrouter()

	 	for router in self.view_info.get_router_list():
			byte_string = byte_string + router
			byte_string = byte_string + self.view_info.get_rid()
	 	byte_string = byte_string + self.view_info.get_ncache()
	 	#byte_string = byte_string + self.view_info.get_cache()

		return byte_string

