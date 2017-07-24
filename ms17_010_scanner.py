#!/usr/bin/python

# Simple SMB MS17-010 Scanner
# By Ch4meleon
#
# Credits:
# - nixawk
# - metasploit - auxiliary/scanner/smb/smb_ms17_010 Metasploit module
#
# Tested working on:
# - Windows XP SP3	(32-bit)
# - Windows 7 SP1 	(64-bit)
# - Windows 10		(64-bit)
#

import os
import sys
import socket
import struct
import logging
from optparse import OptionParser
from ctypes import *


logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__file__)


""" SMB HEADER """
class SMB_HEADER(Structure):
	_pack_ = 1  # Alignment

	_fields_ = [
		("server_component", c_uint32),
		("smb_command", c_uint8),
		("error_class", c_uint8),
		("reserved1", c_uint8),
		("error_code", c_uint16),
		("flags", c_uint8),
		("flags2", c_uint16),
		("process_id_high", c_uint16),
		("signature", c_uint64),
		("reserved2", c_uint16),
		("tree_id", c_uint16),
		("process_id", c_uint16),
		("user_id", c_uint16),
		("multiplex_id", c_uint16)
	]

	def __new__(self, buffer=None):
		return self.from_buffer_copy(buffer)

	def __init__(self, buffer):
		log.debug("server_component : %04x" % self.server_component)
		log.debug("smb_command      : %01x" % self.smb_command)
		log.debug("error_class      : %01x" % self.error_class)
		log.debug("error_code       : %02x" % self.error_code)
		log.debug("flags            : %01x" % self.flags)
		log.debug("flags2           : %02x" % self.flags2)
		log.debug("process_id_high  : %02x" % self.process_id_high)
		log.debug("signature        : %08x" % self.signature)
		log.debug("reserved2        : %02x" % self.reserved2)
		log.debug("tree_id          : %02x" % self.tree_id)
		log.debug("process_id       : %02x" % self.process_id)
		log.debug("user_id          : %02x" % self.user_id)
		log.debug("multiplex_id     : %02x" % self.multiplex_id)


""" Generate SMB Protocol. Pakcet protos in order. """
def generate_smb_proto_payload(*protos):
	hexdata = []
	for proto in protos:
	  hexdata.extend(proto)
	return "".join(hexdata)


""" #1 - Generate a negotiate_proto_request packet. """
def negotiate_proto_request():
	log.debug("generate negotiate request")
	netbios = [
	  '\x00',              # 'Message_Type'
	  '\x00\x00\x54'       # 'Length'
	]

	smb_header = [
	  '\xFF\x53\x4D\x42',  # 'server_component': .SMB
	  '\x72',              # 'smb_command': Negotiate Protocol
	  '\x00\x00\x00\x00',  # 'nt_status'
	  '\x18',              # 'flags'
	  '\x01\x28',          # 'flags2'
	  '\x00\x00',          # 'process_id_high'
	  '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
	  '\x00\x00',          # 'reserved'
	  '\x00\x00',          # 'tree_id'
	  '\x2F\x4B',          # 'process_id'
	  '\x00\x00',          # 'user_id'
	  '\xC5\x5E'           # 'multiplex_id'
	]

	negotiate_proto_request = [
	  '\x00',              # 'word_count'
	  '\x31\x00',          # 'byte_count'

	  # Requested Dialects
	  '\x02',              # 'dialet_buffer_format'
	  '\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',   # 'dialet_name': LANMAN1.0

	  '\x02',              # 'dialet_buffer_format'
	  '\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',   # 'dialet_name': LM1.2X002

	  '\x02',              # 'dialet_buffer_format'
	  '\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',  # 'dialet_name3': NT LANMAN 1.0

	  '\x02',              # 'dialet_buffer_format'
	  '\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00'   # 'dialet_name4': NT LM 0.12
	]

	return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


""" #2 - Generate session setuo andx request. """
def session_setup_andx_request():
	log.debug("generate session setup andx request")
	netbios = [
	  '\x00',              # 'Message_Type'
	  '\x00\x00\x63'       # 'Length'
	]

	smb_header = [
	  '\xFF\x53\x4D\x42',  # 'server_component': .SMB
	  '\x73',              # 'smb_command': Session Setup AndX
	  '\x00\x00\x00\x00',  # 'nt_status'
	  '\x18',              # 'flags'
	  '\x01\x20',          # 'flags2'
	  '\x00\x00',          # 'process_id_high'
	  '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
	  '\x00\x00',          # 'reserved'
	  '\x00\x00',          # 'tree_id'
	  '\x2F\x4B',          # 'process_id'
	  '\x00\x00',          # 'user_id'
	  '\xC5\x5E'           # 'multiplex_id'
	]

	session_setup_andx_request = [
	  '\x0D',              # Word Count
	  '\xFF',              # AndXCommand: No further command
	  '\x00',              # Reserved
	  '\x00\x00',          # AndXOffset
	  '\xDF\xFF',          # Max Buffer
	  '\x02\x00',          # Max Mpx Count
	  '\x01\x00',          # VC Number
	  '\x00\x00\x00\x00',  # Session Key
	  '\x00\x00',          # ANSI Password Length
	  '\x00\x00',          # Unicode Password Length
	  '\x00\x00\x00\x00',  # Reserved
	  '\x40\x00\x00\x00',  # Capabilities
	  '\x26\x00',          # Byte Count
	  '\x00',              # Account
	  '\x2e\x00',          # Primary Domain
	  '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',    # Native OS: Windows 2000 2195
	  '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00',        # Native OS: Windows 2000 5.0
	]

	return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


""" #3 - Generate tree connect andx request. """
def tree_connect_andx_request(ip, userid):
	log.debug("generate tree connect andx request")

	netbios = [
	  '\x00',              # 'Message_Type'
	  '\x00\x00\x47'       # 'Length'
	]

	smb_header = [
	  '\xFF\x53\x4D\x42',  # 'server_component': .SMB
	  '\x75',              # 'smb_command': Tree Connect AndX
	  '\x00\x00\x00\x00',  # 'nt_status'
	  '\x18',              # 'flags'
	  '\x01\x20',          # 'flags2'
	  '\x00\x00',          # 'process_id_high'
	  '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
	  '\x00\x00',          # 'reserved'
	  '\x00\x00',          # 'tree_id'
	  '\x2F\x4B',          # 'process_id'
	  userid,              # 'user_id'
	  '\xC5\x5E'           # 'multiplex_id'
	]

	ipc = "\\\\{}\IPC$\x00".format(ip)
	log.debug("Connecting to {} with UID = {}".format(ipc, userid))

	tree_connect_andx_request = [
		'\x04',              # Word Count
		'\xFF',              # AndXCommand: No further commands
		'\x00',              # Reserved
		'\x00\x00',          # AndXOffset
		'\x00\x00',          # Flags
		'\x01\x00',          # Password Length
		'\x1C\x00',          # Byte Count
		'\x00',              # Password
		ipc.encode(),        # \\xxx.xxx.xxx.xxx\IPC$
		'\x3f\x3f\x3f\x3f\x3f\x00',   # Service
        '\x5f\x54\x52\x45\x45\x50\x41\x54\x48\x5f\x52\x45\x50\x4c\x41\x43\x45\x5f\x5f\x3f\x3f\x3f\x3f\x00'
	]

	length = len("".join(smb_header)) + len("".join(tree_connect_andx_request))
	# netbios[1] = '\x00' + struct.pack('>H', length)
	netbios[1] = struct.pack(">L", length)[-3:]

	return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


""" Generate tran2 request """
def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
	log.debug("generate peeknamedpipe request")
	netbios = [
	  '\x00',              # 'Message_Type'
	  '\x00\x00\x4a'       # 'Length'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',  # 'server_component': .SMB
		'\x25',              # 'smb_command': Trans2
		'\x00\x00\x00\x00',  # 'nt_status'
		'\x18',              # 'flags'
		'\x01\x28',          # 'flags2'
		'\x00\x00',          # 'process_id_high'
		'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
		'\x00\x00',          # 'reserved'
		treeid,
		processid,
		userid,
		multiplex_id
	]

#	smb_header = [
#	  '\xFF\x53\x4D\x42',  # 'server_component': .SMB
#	  '\x25',              # 'smb_command': Trans2
#	  '\x00\x00\x00\x00',  # 'nt_status'
#	  '\x18',              # 'flags'
#	  '\x01\x28',          # 'flags2'
#	  '\x00\x00',          # 'process_id_high'
#	  '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
#	  '\x00\x00',          # 'reserved'
#	  '\x00\x08',          # 'tree_id'
#	  '\x00\x08',          # 'process_id'
#	  '\x00\x08',          # 'user_id'
#	  '\xC5\x5E'           # 'multiplex_id'
#	]
	
	tran_request = [
		'\x10',              # Word Count
		'\x00\x00',          # Total Parameter Count
		'\x00\x00',          # Total Data Count
		'\xff\xff',          # Max Parameter Count
		'\xff\xff',          # Max Data Count
		'\x00',              # Max Setup Count
		'\x00',              # Reserved
		'\x00\x00',          # Flags
		'\x00\x00\x00\x00',  # Timeout: Return immediately
		'\x00\x00',          # Reversed
		'\x00\x00',          # Parameter Count
		'\x4a\x00',          # Parameter Offset
		'\x00\x00',          # Data Count
		'\x4a\x00',          # Data Offset
		'\x02',              # Setup Count
		'\x00',              # Reversed
		'\x23\x00',          # SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
		'\x00\x00',          # SMB Pipe Protocol: FID
		'\x07\x00',
		'\x5c\x50\x49\x50\x45\x5c\x00'  # \PIPE\
	]

	return generate_smb_proto_payload(netbios, smb_header, tran_request)


""" Generate trans2 request. """
def trans2_request(treeid, processid, userid, multiplex_id):
	log.debug("generate tran2 request")
	netbios = [
		'\x00',              # 'Message_Type'
		'\x00\x00\x4f'       # 'Length'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',  # 'server_component': .SMB
		'\x32',              # 'smb_command': Trans2
		'\x00\x00\x00\x00',  # 'nt_status'
		'\x18',              # 'flags'
		'\x07\xc0',          # 'flags2'
		'\x00\x00',          # 'process_id_high'
		'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
		'\x00\x00',          # 'reserved'
		treeid,
		processid,
		userid,
		multiplex_id
	]

	trans2_request = [
		'\x0f',              # Word Count
		'\x0c\x00',          # Total Parameter Count
		'\x00\x00',          # Total Data Count
		'\x01\x00',          # Max Parameter Count
		'\x00\x00',          # Max Data Count
		'\x00',              # Max Setup Count
		'\x00',              # Reserved
		'\x00\x00',          # Flags
		'\xa6\xd9\xa4\x00',  # Timeout: 3 hours, 3.622 seconds
		'\x00\x00',          # Reversed
		'\x0c\x00',          # Parameter Count
		'\x42\x00',          # Parameter Offset
		'\x00\x00',          # Data Count
		'\x4e\x00',          # Data Offset
		'\x01',              # Setup Count
		'\x00',              # Reserved
		'\x0e\x00',          # subcommand: SESSION_SETUP
		'\x00\x00',          # Byte Count
		'\x0c\x00' + '\x00' * 12
	]

	return generate_smb_proto_payload(netbios, smb_header, trans2_request)


""" Check if MS17_010 SMB Vulnerability exists. """	
def scan_host(ip, port=445):
	try:
		buffersize = 1024
		timeout = 5.0

		# Send smb request based on socket.
		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.settimeout(timeout)
		client.connect((ip, port))

		#1 SMB - Negotiate Protocol Request
		raw_proto = negotiate_proto_request()
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		#2 SMB - Session Setup AndX Request
		raw_proto = session_setup_andx_request()
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
		smb = SMB_HEADER(smb_header)

		user_id = struct.pack('<H', smb.user_id)

		# parse native_os from Session Setup Andx Response
		session_setup_andx_response = tcp_response[36:]
		native_os = session_setup_andx_response[9:].split('\x00')[0]

		#3 SMB - Tree Connect AndX Request
		raw_proto = tree_connect_andx_request(ip, user_id)
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
		smb = SMB_HEADER(smb_header)

		tree_id = struct.pack('<H', smb.tree_id)
		process_id = struct.pack('<H', smb.process_id)
		user_id = struct.pack('<H', smb.user_id)
		multiplex_id = struct.pack('<H', smb.multiplex_id)

		# SMB - PeekNamedPipe Request
		raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		nt_status2 = smb_header[5:9]
		nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)

		response_code = "".join("{:02x}".format(ord(c)) for c in nt_status)
		
		# 050200c0 - STATUS_INSUFF_SERVER_RESOURCES - VULNERABLE
		# 02000500 - TID INVALID - ERROR
		# 02005b00 - Bad userid - NOT VULNERABLE
		# 080000c0 - STATUS_INVALID_HANDLE
		# 220000c0 - STATUS_ACCESS_DENIED

		# print response_code

		if response_code == "050200c0":
			log.info("[+] %s, VULNERABLE (STATUS_INSUFF_SERVER_RESOURCES)" % (ip))

		elif (response_code == "080000c0") or (response_code == "02005b00"):
			log.info("[-] %s, NOT VULNERABLE" % (ip))

		elif (response_code == "02000500"):
			log.info("[-] %s, ERROR (TID INVALID)" % (ip))
			
		elif (response_code == "220000c0"):
			log.info("[-] %s, NOT VULNERABLE (STATUS_ACCESS_DENIED)" % (ip))
			
		else:
			log.info("[-] %s, UNABLE TO DETERMINE (%s)" % (ip, response_code))

	except Exception as err:
		log.error("[-] {}, EXCEPTION: {}".format(ip, str(err).upper()))
		
	finally:
		client.close()


def ping(address):
	return not os.system('ping %s -n 1' % (address,))

if __name__ == '__main__':
	parser = OptionParser(usage="usage: %prog -t 10.0.0.2", version="%prog 1.0")
	
	parser.add_option("-t", "--target",
					  action="store",
					  dest="target_to_scan",
					  default="",
					  help="Scan a target IP/Host.",)

	parser.add_option("-l", "--list",
					  action="store",
					  dest="list_to_scan",
					  default="",
					  help="Scan a list of IP(s)/Host(s).",)

	(options, args) = parser.parse_args()

	target_to_scan = options.target_to_scan
	list_to_scan = options.list_to_scan

	if (target_to_scan == "") and (list_to_scan == ""):
		parser.error("Wrong number of arguments. Need either -t or -l.")

	log.info("Simple SMB MS17-010 Scanner")
	log.info("[*] Scanning Started...")

	if (target_to_scan != ""):
		scan_host(target_to_scan)
	else:
		lines = open(list_to_scan).readlines()
		for line in lines:
			line = line.strip()
			if line != "":
				scan_host(line)

# ===========
# REFERENCES:
# ===========
# https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
# https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
# https://www.symantec.com/security_response/vulnerability.jsp?bid=96707
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/[MS-SMB2]-151016.pdf
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx
# https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
# https://community.rapid7.com/community/metasploit/blog/2017/04/03/introducing-rubysmb-the-protocol-library-nobody-else-wanted-to-write
# https://msdn.microsoft.com/en-us/library/ee441741.aspx
# https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_smb.py
# http://stackoverflow.com/questions/38735421/packing-an-integer-number-to-3-bytes-in-python
# https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
# https://msdn.microsoft.com/en-us/library/ee441884.aspx

