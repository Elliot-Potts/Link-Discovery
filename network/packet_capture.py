import asyncio
import scapy.all as scapy
from scapy.contrib.cdp import (
    CDPv2_HDR, CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, 
    CDPMsgPortID, CDPMsgCapabilities, CDPMsgNativeVLAN, CDPMsgDuplex,
    CDPMsgMgmtAddr
)
from scapy.contrib.lldp import (
    LLDPDU, LLDPDUSystemName, LLDPDUPortID, LLDPDUPortDescription,
    LLDPDUManagementAddress, LLDPDUSystemCapabilities, LLDPDUChassisID, 
    LLDPDUTimeToLive, LLDPDUSystemDescription
)
from utils.logger import logger
import ipaddress

async def capture_packet(interface, protocol):
    def stop_filter(pkt):
        return CDPv2_HDR in pkt or LLDPDU in pkt

    filter_str = "ether dst 01:00:0c:cc:cc:cc" if protocol == "CDP" else "ether dst 01:80:c2:00:00:0e"
    
    packet = await asyncio.get_event_loop().run_in_executor(
        None, 
        lambda: scapy.sniff(iface=interface, filter=filter_str, stop_filter=stop_filter, count=1)
    )
    return packet[0] if packet else None

def parse_cdp_packet(packet):
    cdp_info = {}
    if CDPv2_HDR in packet:
        cdp_layer = packet[CDPv2_HDR]
        logger.debug(f"CDP Layer: {cdp_layer.summary()}")

        for tlv in cdp_layer.msg:
            logger.debug(f"Processing TLV: {type(tlv).__name__}")
            if isinstance(tlv, CDPMsgDeviceID):
                cdp_info['System Name'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgMgmtAddr):
                mgmt_addrs = []
                for addr in tlv.addr:
                    if hasattr(addr, 'addr'):
                        mgmt_addrs.append(str(addr.addr))
                cdp_info['Management Addresses'] = ', '.join(mgmt_addrs)
            elif isinstance(tlv, CDPMsgSoftwareVersion):
                cdp_info['Software Version'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgPlatform):
                cdp_info['Platform'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgCapabilities):
                cdp_info['Capabilities'] = str(tlv.cap)
            elif isinstance(tlv, CDPMsgPortID):
                cdp_info['Port ID'] = tlv.iface.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgNativeVLAN):
                cdp_info['Native VLAN'] = tlv.vlan
            elif isinstance(tlv, CDPMsgDuplex):
                cdp_info['Duplex'] = 'Full' if tlv.duplex == 1 else 'Half'
            
        cdp_info['Version'] = cdp_layer.vers
        cdp_info['TTL'] = cdp_layer.ttl

    logger.debug(f"Parsed CDP Info: {cdp_info}")
    return cdp_info

def parse_lldp_packet(packet):
    lldp_info = {}
    
    if LLDPDU in packet:
        # Chassis ID
        chassis_id_layer = packet.getlayer(LLDPDUChassisID)
        if chassis_id_layer:
            lldp_info['Chassis ID'] = f"{chassis_id_layer.subtype}: {chassis_id_layer.id}"
        
        # System Name
        system_name_layer = packet.getlayer(LLDPDUSystemName)
        if system_name_layer:
            lldp_info['System Name'] = system_name_layer.system_name.decode('utf-8', errors='ignore')
            
        # Management Address
        mgmt_addr_layer = packet.getlayer(LLDPDUManagementAddress)
        if mgmt_addr_layer:
            try:
                # Convert hexadecimal to integer
                ip_int = int.from_bytes(mgmt_addr_layer.management_address, byteorder='big')
                # Convert integer to IP address
                ip_address = str(ipaddress.ip_address(ip_int))
                lldp_info['Management Address'] = ip_address
                logger.debug(f"Management Address: {ip_address}")
            except Exception as e:
                logger.error(f"Error converting management address: {e}")
                lldp_info['Management Address'] = str(mgmt_addr_layer.management_address)
        
        # System Description
        system_desc_layer = packet.getlayer(LLDPDUSystemDescription)
        if system_desc_layer:
            lldp_info['System Description'] = system_desc_layer.description.decode('utf-8', errors='ignore')

        # Port ID
        port_id_layer = packet.getlayer(LLDPDUPortID)
        if port_id_layer:
            lldp_info['Port ID'] = port_id_layer.id.decode('utf-8', errors='ignore')

        # Port Description
        port_desc_layer = packet.getlayer(LLDPDUPortDescription)
        if port_desc_layer:
            lldp_info['Port Description'] = port_desc_layer.description.decode('utf-8', errors='ignore')
        
        # Time To Live
        ttl_layer = packet.getlayer(LLDPDUTimeToLive)
        if ttl_layer:
            lldp_info['TTL'] = ttl_layer.ttl

    logger.debug(f"Parsed LLDP Info: {lldp_info}")
    return lldp_info

async def capture_and_parse_packets(interface, protocols):
    async def capture_protocol(protocol):
        for _ in range(60):
            packet = await capture_packet(interface, protocol)
            if packet:
                if protocol == "CDP" and CDPv2_HDR in packet:
                    logger.debug("CDP Packet found. Parsing...")
                    return {"CDP": parse_cdp_packet(packet)}
                elif protocol == "LLDP" and LLDPDU in packet:
                    logger.debug("LLDP Packet found. Parsing...")
                    return {"LLDP": parse_lldp_packet(packet)}
            await asyncio.sleep(1)
        return None

    tasks = [asyncio.create_task(capture_protocol(protocol)) for protocol in protocols]
    remaining_time = 60

    while tasks and remaining_time > 0:
        done, pending = await asyncio.wait(tasks, timeout=1, return_when=asyncio.FIRST_COMPLETED)
        
        for task in done:
            result = await task
            if result:
                yield result
                tasks.remove(task)
        
        remaining_time -= 1
        yield remaining_time

    # Cancel any remaining tasks
    for task in tasks:
        task.cancel()

    # Wait for cancelled tasks to finish
    await asyncio.gather(*tasks, return_exceptions=True)