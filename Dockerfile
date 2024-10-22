FROM python:3.10.15 as base

USER root

COPY requirements.txt /src/requirements.txt
RUN pip install -r /src/requirements.txt --no-cache-dir


COPY revoke_unused_creds.py /src/revoke_unused_creds.py


#execute the revoke_unused_creds.py
ENTRYPOINT ["python", "/src/revoke_unused_creds.py"]





