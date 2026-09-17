# Deliberately-vulnerable demo target. Runs on the same docker bridge as the
# agent sandbox so the web specialist can reach it by IP.
FROM python:3.12-slim
RUN pip install --no-cache-dir flask
COPY vuln_app.py /app/vuln_app.py
WORKDIR /app
EXPOSE 5000
CMD ["python", "vuln_app.py"]
