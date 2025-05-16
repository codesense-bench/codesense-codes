FROM ibmjava:8-sdk

WORKDIR /

RUN apt update -y && \
    apt install -y ant python3 python3-pip

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY /entrypoint.sh .
ENTRYPOINT ["/entrypoint.sh"]
