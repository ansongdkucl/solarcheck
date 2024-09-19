from pysnmp.hlapi import *
import os

snmpv3_user = os.environ.get('snmpv3_user', 'default_user') 
snmpv3_auth_key = os.environ.get('snmpv3_auth_key', 'default_auth_key') 
snmpv3_priv_key = os.environ.get('snmpv3_priv_key', 'default_priv_key')

def check_snmpv3_configuration(target_ip, snmpv3_user, snmpv3_auth_key, snmpv3_priv_key, snmpv3_priv_protocol):
    user = UsmUserData(snmpv3_user, snmpv3_auth_key, snmpv3_priv_key, authProtocol=usmHMACSHAAuthProtocol, privProtocol=snmpv3_priv_protocol)
    context = ContextData()
    snmp_engine = SnmpEngine()

    target = UdpTransportTarget((target_ip, 161))

    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(snmp_engine, user, target, context, ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
    ))

    if errorIndication:
        return False
    else:
        return True

def check_snmpv2_configuration(target_ip, community_string):
    target = UdpTransportTarget((target_ip, 161))
    community_data = CommunityData('public', community_string, mpModel=0)

    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(), community_data, target, ContextData(), ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
    ))

    if errorIndication:
        return False
    else:
        return True

if __name__ == '__main__':
    target_ips = ['172.17.57.240', '172.17.57.241', '172.17.57.242', '172.17.57.243','172.17.52.19']  # Replace with your list of IP addresses
    snmpv3_auth_protocol = usmAesCfb128Protocol  # Change this to your desired privacy protocol
    #community_string = 'blooming'  # Replace with your desired community string

    for ip in target_ips:
        if check_snmpv3_configuration(ip, snmpv3_user, snmpv3_auth_key, snmpv3_priv_key, snmpv3_auth_protocol):
            #print(f"SNMPv3 is enabled and configured on {ip}")
            pass

        else:
            print(f"No SNMPv3 found on {ip}")
