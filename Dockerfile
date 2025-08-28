FROM python:3.13-rc-alpine
LABEL maintainer="Steven George <steven.pysyslog@hardtechnology.net>"
WORKDIR /pysyslog
COPY ./src/ /pysyslog/
EXPOSE 514/udp
RUN pip3 install --no-cache-dir boto3
HEALTHCHECK --interval=1m --timeout=5s --start-period=30s CMD netstat -aun | grep 514 > /dev/null; if [ 0 != $? ]; then exit 1; fi;
CMD ["/pysyslog/start.sh"]
