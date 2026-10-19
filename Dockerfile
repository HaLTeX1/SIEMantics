FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt

COPY app ./app
# Az agent telepito ezeket szolgalja ki (izolalo script Linuxra es Windowsra).
COPY wazuh/active-response ./wazuh/active-response

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
