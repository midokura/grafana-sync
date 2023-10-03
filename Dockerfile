FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY grafana_sync.py ./
ENTRYPOINT [ "./grafana_sync.py" ]
CMD [ "--help" ]