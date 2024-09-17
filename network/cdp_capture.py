import asyncio
import scapy.all as scapy
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, CDPMsgCapabilities, CDPMsgNativeVLAN, CDPMsgDuplex, CDPMsgMgmtAddr
from utils.logger import logger


async def capture_cdp_packet(interface, timeout=1):
    def stop_filter(pkt):
        return CDPv2_HDR in pkt

    packet = await asyncio.get_event_loop().run_in_executor(
        None, 
        lambda: scapy.sniff(iface=interface, filter="ether dst 01:00:0c:cc:cc:cc", stop_filter=stop_filter, timeout=timeout, count=1)
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


async def capture_and_parse_cdp(interface):
    for i in range(60):
        cdp_packet = await capture_cdp_packet(interface)
        if cdp_packet:
            cdp_info = parse_cdp_packet(cdp_packet)
            if cdp_info and len(cdp_info) > 2:  # More than just Version and TTL indicates complete CDP packet
                yield cdp_info
                return  # Stop generator after yielding CDP info
        yield 60 - i
        