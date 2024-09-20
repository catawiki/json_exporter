FROM python:3.8-alpine

ARG USERNAME=json_exporter

ADD pyproject.toml requirements.txt /tmp/code/
ADD json_exporter /tmp/code/json_exporter/

WORKDIR /tmp/code

RUN pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir  -r requirements.txt \
  && pip install --no-cache-dir . \
  && adduser -H -S -s /sbin/nologin -g "JSON Exporter" ${USERNAME} \
  && rm -rf /tmp/code

WORKDIR /

USER ${USERNAME}

ENTRYPOINT [ "/usr/local/bin/json_exporter" ]
