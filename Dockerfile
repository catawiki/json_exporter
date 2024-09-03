FROM python:alpine3.13

ADD ./ /tmp/code

WORKDIR /tmp/code

RUN pip install --upgrade pip \
  && pip install -r requirements.txt \
  && pip install . \
  && rm -rf /tmp/code

WORKDIR /

ENTRYPOINT [ "/usr/local/bin/json_exporter" ]
