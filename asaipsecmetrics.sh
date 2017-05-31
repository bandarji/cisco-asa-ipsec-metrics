#!/bin/sh

# tCollector ingestion loop for domestic datacenter cisco ASA IPSEC tunnels
# Sean Jain Ellis <sellis@bandarji.com>

function pull_asa_ipsec_metrics() {
    # args = fw.addr snmp.community sitename
    # Docker container needs net-snmp-utils RPM
    FW_ADDR="${1:-0}" FW_SNMP_COMMUNITY="${2:-0}" FW_SNMP_SITE="${3:-0}" \
        /work/asaipsecmetrics.py


function main() {
    # Examples -- this needs some love
    local INTERVAL=600
    while : ; do
        pull_asa_ipsec_metrics 192.168.20.5 snmprocomm1 area51
        pull_asa_ipsec_metrics 10.99.99.99 sNmP007 yuccamountain
        /bin/sleep ${INTERVAL}
    done
}

main "${@}"
