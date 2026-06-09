FROM python:3.11-alpine

# Minimal attack surface — Alpine has no bash, no curl, no wget by default
RUN pip install --no-cache-dir requests==2.32.3

WORKDIR /sandbox

# Non-root user — even if code escapes Python, no system privileges
RUN adduser -D -u 1000 sandboxuser
USER sandboxuser

CMD ["python", "-c", "print('sandbox ready')"]
