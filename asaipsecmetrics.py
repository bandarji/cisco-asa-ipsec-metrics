#!/usr/bin/env python

# Pull cisco ASA IPSEC metrics for tCollector to pass to WaveFront
# Maintainer: Sean Jain Ellis

from os import environ as os_environ
from pprint import pprint as pretty
from subprocess import PIPE as ppipe
from subprocess import Popen as popen
from time import time as s_epoch

class Job(object):

    def __init__(self, hostname=None, snmp_community=None, sitename=None):
        if not hostname or not snmp_community or not sitename:
            raise SystemExit('SNMP query parameters not supplied')
        else:
            self.magic = 'd112771bccfff39744ce'
            self.hostname = hostname
            self.snmp_community = snmp_community
            self.sitename = sitename
            self.snmp_bulkwalk = '/usr/bin/snmpbulkwalk'
            self.snmp_oid_dict = {
                'CISCO_ASA_IPSEC_BASE': '.1.3.6.1.4.1.9.9.171.1',
                'cikeTunRemoteValue': '.1.3.6.1.4.1.9.9.171.1.2.3.1.7',
                'cipSecTunIkeTunnelIndex': '.1.3.6.1.4.1.9.9.171.1.3.2.1.2',
                'cipSecTunRemoteAddr': '.1.3.6.1.4.1.9.9.171.1.3.2.1.5',
                'cipSecTunHcInOctets': '.1.3.6.1.4.1.9.9.171.1.3.2.1.27',
                'cipSecTunHcOutOctets': '.1.3.6.1.4.1.9.9.171.1.3.2.1.40',
                'cipSecEndPtLocalAddr1': '.1.3.6.1.4.1.9.9.171.1.3.3.1.4',
                'cipSecEndPtLocalAddr2': '.1.3.6.1.4.1.9.9.171.1.3.3.1.5',
                'cipSecEndPtRemoteAddr1': '.1.3.6.1.4.1.9.9.171.1.3.3.1.10',
                'cipSecEndPtRemoteAddr2': '.1.3.6.1.4.1.9.9.171.1.3.3.1.11'
            }
            self.tunnel_dict = {}
            self.snmp_out = []
            self.now = int(s_epoch()) # not accurate
            self.build_tunnel_dict()
            self.dump_metrics()

    def build_tunnel_dict(self):
        snmp_oid = self.snmp_oid_dict.get('CISCO_ASA_IPSEC_BASE', None)
        if snmp_oid:
            command = "{} -v2c -OQen -c {} {} {}".\
                format(
                    self.snmp_bulkwalk,
                    self.snmp_community,
                    self.hostname,
                    snmp_oid
                )
            self.snmp_out = run(command.split())
            self.tunnel_dict = {}
            for line in self.snmp_out:
                if line.startswith('.1.3.6.1.4.1.9.9.171.1.3.2.1.2.'):
                    key = line.split('=')[0].strip().split('.')[-1]
                    self.tunnel_dict[key] = {}
                    self.tunnel_dict[key]['bytesin'] = self.store_metric(
                        key, self.snmp_oid_dict.get(
                            'cipSecTunHcInOctets', self.magic
                        )
                    )
                    self.tunnel_dict[key]['bytesout'] = self.store_metric(
                        key, self.snmp_oid_dict.get(
                            'cipSecTunHcOutOctets', self.magic
                        )
                    )
                    self.tunnel_dict[key]['leftaddr'] = self.store_hex_metric(
                        key, self.snmp_oid_dict.get(
                            'cipSecEndPtLocalAddr1', self.magic
                        )
                    )
                    self.tunnel_dict[key]['rightaddr'] = self.store_hex_metric(
                        key, self.snmp_oid_dict.get(
                            'cipSecEndPtRemoteAddr1', self.magic
                        )
                    )
                    self.tunnel_dict[key]['leftmask'] = self.store_hex_metric(
                        key, self.snmp_oid_dict.get(
                            'cipSecEndPtLocalAddr2', self.magic
                        )
                    )
                    self.tunnel_dict[key]['rightmask'] = self.store_hex_metric(
                        key, self.snmp_oid_dict.get(
                            'cipSecEndPtRemoteAddr2', self.magic
                        )
                    )
                    self.tunnel_dict[key]['peeraddr'] = self.get_peer_addr(key)
        else:
            raise SystemExit('Invalid SNMP Object Identifier (OID).')

    def dump_metrics(self):
        metrics = self.tunnel_dict
        for k, v in metrics.items():
            bytesin = v.get('bytesin', '0')
            bytesout = v.get('bytesout', '0')
            leftaddr = v.get('leftaddr', '0.0.0.0')
            leftmask = v.get('leftmask', '0.0.0.0')
            rightaddr = v.get('rightaddr', '0.0.0.0')
            rightmask = v.get('rightmask', '0.0.0.0')
            peeraddr = v.get('peeraddr', '0.0.0.0')
            if (leftaddr != leftmask
                    and rightaddr != rightmask
                    or bytesin == 0
                    or bytesout == 0):
                msg = "fw.ipsec.bytesin {} {} fw={} left={} right={} peer={}".\
                    format(
                        self.now,
                        bytesin,
                        self.sitename,
                        "{}.{}".format(leftaddr, leftmask),
                        "{}.{}".format(rightaddr, rightmask),
                        peeraddr
                    )
                print(msg)
                msg = "fw.ipsec.bytesout {} {} fw={} left={} right={} peer={}".\
                    format(
                        self.now,
                        bytesout,
                        self.sitename,
                        "{}.{}".format(leftaddr, leftmask),
                        "{}.{}".format(rightaddr, rightmask),
                        peeraddr
                    )
                print(msg)

    def get_peer_addr(self, key):
        ike_index = self.magic
        snmp_oid =\
            self.snmp_oid_dict.get('cipSecTunIkeTunnelIndex', self.magic)
        for line in self.snmp_out:
            if line.startswith(snmp_oid + '.' + key):
                ike_index = line.split('=')[1].strip()
                break
        snmp_oid =\
            self.snmp_oid_dict.get('cikeTunRemoteValue', self.magic)
        for line in self.snmp_out:
            if line.startswith(snmp_oid + '.' + ike_index):
                return line.split('=')[1].replace('"', '').strip()

    def store_hex_metric(self, key, oid_key):
        for line in self.snmp_out:
            if line.startswith(oid_key + '.' + key):
                return ".".join([str(int(x, 16)) for x in \
                    line.split('=')[1].replace('"', '').strip().split()])

    def store_metric(self, key, oid_key):
        for line in self.snmp_out:
            if line.startswith(oid_key + '.' + key):
                return line.split('=')[1].replace('"', '').strip()


def run(cmd_list=None):
    """ Run a command and return output as a list """
    if cmd_list:
        try:
            proc = popen(cmd_list, stdout=ppipe)
            return proc.communicate()[0].split('\n')
        except OSError:
            return ['ERROR: OSError']

def main():
    fw_params = {
        'hostname': os_environ.get('FW_ADDR', None),
        'snmp_community': os_environ.get('FW_SNMP_COMMUNITY', None),
        'sitename': os_environ.get('FW_SNMP_SITE', None)
    }
    Job(**fw_params)

if __name__ == '__main__':
    main()
