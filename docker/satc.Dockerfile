FROM smile0304/satc:latest

USER root
WORKDIR /home/satc/SaTC
ENV PATH="/home/satc/.virtualenvs/SaTC/bin:${PATH}"
COPY satc-entrypoint.sh /usr/local/bin/firmhound-satc
RUN chmod 755 /usr/local/bin/firmhound-satc
ENTRYPOINT ["/usr/local/bin/firmhound-satc"]
