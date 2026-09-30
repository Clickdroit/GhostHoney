FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000 2222 2323

ENTRYPOINT ["python", "main.py"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
