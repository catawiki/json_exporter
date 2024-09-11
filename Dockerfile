FROM python:3.12-alpine

ARG USERNAME=json_exporter

ADD ./ /tmp/code

WORKDIR /tmp/code

RUN pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir  -r requirements.txt \
  && pip install --no-cache-dir . \
  && adduser -H -S -s /sbin/nologin -g "JSON Exporter" ${USERNAME} \
  && rm -rf /tmp/code

WORKDIR /

USER ${USERNAME}

ENTRYPOINT [ "/usr/local/bin/json_exporter" ]
