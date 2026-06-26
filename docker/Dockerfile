FROM python:3.11-alpine

RUN pip install --no-cache-dir requests==2.32.3

RUN adduser -D -u 1000 sandboxuser

WORKDIR /sandbox
COPY sandbox_runner.py /sandbox/sandbox_runner.py

RUN chown -R sandboxuser:sandboxuser /sandbox

USER sandboxuser

ENTRYPOINT ["python", "sandbox_runner.py"]
