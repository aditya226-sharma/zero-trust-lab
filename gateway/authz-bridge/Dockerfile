FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 9191
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:9191", "app:app"]
