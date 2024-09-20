import asyncio
import scapy.all as scapy
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, CDPMsgCapabilities, CDPMsgNativeVLAN, CDPMsgDuplex, CDPMsgMgmtAddr
from scapy.contrib.lldp import (
    LLDPDU, LLDPDUSystemName, LLDPDUPortID, LLDPDUPortDescription,
    LLDPDUManagementAddress, LLDPDUSystemCapabilities, LLDPDUChassisID, 
    LLDPDUTimeToLive, LLDPDUSystemDescription
)
from utils.logger import logger

async def capture_packet(interface, protocol, timeout=1):
    def stop_filter(pkt):
        return CDPv2_HDR in pkt or LLDPDU in pkt

    filter_str = "ether dst 01:00:0c:cc:cc:cc" if protocol == "CDP" else "ether dst 01:80:c2:00:00:0e"
    
    packet = await asyncio.get_event_loop().run_in_executor(
        None, 
        lambda: scapy.sniff(iface=interface, filter=filter_str, stop_filter=stop_filter, timeout=timeout, count=1)
    )
    return packet[0] if packet else None

def parse_cdp_packet(packet):
    cdp_info = {}
    if CDPv2_HDR in packet:
        cdp_layer = packet[CDPv2_HDR]
        logger.debug(f"CDP Layer: {cdp_layer.summary()}")
        cdp_info['Version'] = cdp_layer.vers
        cdp_info['TTL'] = cdp_layer.ttl

        for tlv in cdp_layer.msg:
            logger.debug(f"Processing TLV: {type(tlv).__name__}")
            if isinstance(tlv, CDPMsgDeviceID):
                cdp_info['Device ID'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgSoftwareVersion):
                cdp_info['Software Version'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgPlatform):
                cdp_info['Platform'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgPortID):
                cdp_info['Port ID'] = tlv.iface.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgCapabilities):
                cdp_info['Capabilities'] = str(tlv.cap)
            elif isinstance(tlv, CDPMsgNativeVLAN):
                cdp_info['Native VLAN'] = tlv.vlan
            elif isinstance(tlv, CDPMsgDuplex):
                cdp_info['Duplex'] = 'Full' if tlv.duplex == 1 else 'Half'
            elif isinstance(tlv, CDPMsgMgmtAddr):
                mgmt_addrs = []
                for addr in tlv.addr:
                    if hasattr(addr, 'addr'):
                        mgmt_addrs.append(str(addr.addr))
                cdp_info['Management Addresses'] = ', '.join(mgmt_addrs)

    logger.debug(f"Parsed CDP Info: {cdp_info}")
    return cdp_info

def parse_lldp_packet(packet):
    lldp_info = {}
    
    if LLDPDU in packet:
        # TODO - Implement LLDP Packet Parsing
        pass

    logger.debug(f"Parsed LLDP Info: {lldp_info}")
    return lldp_info

async def capture_and_parse_packets(interface, protocols):
    for i in range(60):
        for protocol in protocols:
            packet = await capture_packet(interface, protocol)
            if packet:
                if protocol == "CDP" and CDPv2_HDR in packet:
                    info = parse_cdp_packet(packet)
                elif protocol == "LLDP" and LLDPDU in packet:
                    info = parse_lldp_packet(packet)
                else:
                    continue

                if info and len(info) > 1:  # Ensure we have meaningful information
                    yield {protocol: info}
                    return  # Stop generator after yielding packet info
        yield 60 - i