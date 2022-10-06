FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY grafana-sync.py ./
ENTRYPOINT [ "./grafana-sync.py" ]
CMD [ "--help" ]