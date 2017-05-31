#!/bin/bash

# Runs tCollector within the Docker container, throwing metrics to WaveFront.

function main() {
  local metricsdst="yourwavefrontproxy.example.com"
  /usr/bin/python /work/tcollector/tcollector.py -L ${metricsdst} \
    -p 4242 -t host=tcoll -P /var/run/tcollector.pid --reconnect-interval 0 \
    --max-bytes 10000000 --backup-count 0 --logfile /work/tcollector.log \
    --no-tcollector-stats --dedup-interval=600
}

main "${@}"
