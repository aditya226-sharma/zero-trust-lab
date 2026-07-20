FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography
COPY app.py .
CMD ["python3", "app.py"]
