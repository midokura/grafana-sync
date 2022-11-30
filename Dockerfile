FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY grafana-sync.py ./
ENTRYPOINT [ "./grafana-sync.py" ]
CMD [ "--help" ]