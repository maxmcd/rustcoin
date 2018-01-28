FROM python:3.6

RUN mkdir -p /opt/chaindata
RUN mkdir -p /opt/python
WORKDIR /opt/python

COPY ./requirements.txt /opt/python
RUN pip install --no-cache-dir -r ./requirements.txt

COPY . /opt/python

CMD ["python", "blockchain.py"]