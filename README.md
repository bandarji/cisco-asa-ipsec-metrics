# cisco ASA IPSEC Processing

## Purpose

Program collects metrics from cisco ASA targets. tCollector ships processed
metrics to WaveFront, but output easy enough to change to any destination.

## Files

| File | Description |
| --- | --- |
| [asaipsecmetrics.py](asaipsecmetrics.py) | Collect cisco ASA IPSEC metrics |
| [asaipsecmetrics.sh](asaipsecmetrics.sh) | tCollector metrics puller (you must edit) |
| [Dockerfile](Dockerfile) | Dockerfile for container build |
| [LICENSE](LICENSE) | MIT license |
| [tcollector.sh](tcollector.sh) | tCollector script (you must edit) |

* To Do
  * Create metrics Docker container
  * Create infrastructure YAML
  * Build smaller container (Alpine, maybe)

## SNMP Object Identifiers of Interest


### `cikeTunRemoteValue`

```
.1.3.6.1.4.1.9.9.171.1.2.3.1.7.205471744 = STRING: "150.106.51.71"
```

### `cipSecTunIkeTunnelIndex`

```
.1.3.6.1.4.1.9.9.171.1.3.2.1.2.35568 = INTEGER: 205471744
.1.3.6.1.4.1.9.9.171.1.3.2.1.2.35570 = INTEGER: 205471744
.1.3.6.1.4.1.9.9.171.1.3.2.1.2.35571 = INTEGER: 205471744
.1.3.6.1.4.1.9.9.171.1.3.2.1.2.35684 = INTEGER: 205471744
```

### `cipSecTunRemoteAddr`

```
.1.3.6.1.4.1.9.9.171.1.3.2.1.5.35568 = Hex-STRING: 96 6A 33 47
.1.3.6.1.4.1.9.9.171.1.3.2.1.5.35570 = Hex-STRING: 96 6A 33 47
.1.3.6.1.4.1.9.9.171.1.3.2.1.5.35571 = Hex-STRING: 96 6A 33 47
.1.3.6.1.4.1.9.9.171.1.3.2.1.5.35684 = Hex-STRING: 96 6A 33 47
```

### `cipSecTunHcInOctets`

```
.1.3.6.1.4.1.9.9.171.1.3.2.1.27.35568 = Counter64: 107621208
.1.3.6.1.4.1.9.9.171.1.3.2.1.27.35570 = Counter64: 635370939
.1.3.6.1.4.1.9.9.171.1.3.2.1.27.35571 = Counter64: 285636105
.1.3.6.1.4.1.9.9.171.1.3.2.1.27.35684 = Counter64: 601673941
```

### `cipSecTunHcOutOctets`

```
.1.3.6.1.4.1.9.9.171.1.3.2.1.40.35568 = Counter64: 97177146
.1.3.6.1.4.1.9.9.171.1.3.2.1.40.35570 = Counter64: 924583970
.1.3.6.1.4.1.9.9.171.1.3.2.1.40.35571 = Counter64: 133845086
.1.3.6.1.4.1.9.9.171.1.3.2.1.40.35684 = Counter64: 862410728
.1.3.6.1.4.1.9.9.171.1.3.2.1.40.36382 = Counter64: 2598722134012
```

### `cipSecEndPtLocalAddr1`

* Left network

```
.1.3.6.1.4.1.9.9.171.1.3.3.1.4.35568.1 = Hex-STRING: 0A 0A 0A 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.4.35570.1 = Hex-STRING: 0A 0A 0A 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.4.35571.1 = Hex-STRING: 0A 0A 0A 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.4.35684.1 = Hex-STRING: 0A 0A 0A 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.4.36382.1 = Hex-STRING: 0A 0A 0A 00
```

### `cipSecEndPtLocalAddr2`

* Left mask

```
.1.3.6.1.4.1.9.9.171.1.3.3.1.5.35568.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.5.35570.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.5.35571.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.5.35684.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.5.36382.1 = Hex-STRING: FF FF FF 00
```

### `cipSecEndPtRemoteAddr1`

* Right network

```
.1.3.6.1.4.1.9.9.171.1.3.3.1.10.35568.1 = Hex-STRING: 0A 0A 0B 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.10.35570.1 = Hex-STRING: 0A 0A 0B 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.10.35571.1 = Hex-STRING: 0A 0A 0B 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.10.35684.1 = Hex-STRING: 0A 0A 0B 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.10.36382.1 = Hex-STRING: 0A 0A 0B 00
```

### `cipSecEndPtRemoteAddr2`

* Right mask

```
.1.3.6.1.4.1.9.9.171.1.3.3.1.11.35568.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.11.35570.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.11.35571.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.11.35684.1 = Hex-STRING: FF FF FF 00
.1.3.6.1.4.1.9.9.171.1.3.3.1.11.36382.1 = Hex-STRING: FF FF FF 00
```
