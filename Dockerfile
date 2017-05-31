FROM centos:centos7
MAINTAINER Sean Jain Ellis <sellis@bandarji.com>

RUN yum -y update && yum clean all
RUN yum -y install git net-snmp-utils

RUN mkdir /work
WORKDIR /work

RUN cd /work && git clone git://github.com/OpenTSDB/tcollector.git
RUN rm -f /work/tcollector/collectors/0/* \
    /work/tcollector/collectors/300/* \
    /work/tcollector/collectors/900/*

ADD asaipsecmetrics.py /work
ADD tcollector.sh /work/tcollector
ADD asaipsecmetrics.sh /work/tcollector/collectors/0
RUN chmod +x /work/asaipsecmetrics.py
RUN chmod +x /work/tcollector/tcollector.sh
RUN chmod +x /work/tcollector/collectors/0/asaipsecmetrics.sh

CMD ["/bin/bash", "/work/tcollector/tcollector.sh"]
