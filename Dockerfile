FROM python:3

WORKDIR /usr/src

COPY . .

RUN pip install --editable .
