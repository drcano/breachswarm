# Deliberately-vulnerable demo targets. Runs on the docker bridge so the agent
# sandbox reaches it by IP. Pick the app with -e APP=<file> (default: SSTI app).
FROM python:3.12-slim
RUN pip install --no-cache-dir flask
COPY *.py /app/
WORKDIR /app
ENV APP=vuln_app.py
EXPOSE 5000
CMD ["sh", "-c", "python $APP"]
