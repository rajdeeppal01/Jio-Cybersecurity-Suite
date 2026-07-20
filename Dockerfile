FROM python:3.11-slim
WORKDIR /app
COPY --chown=1000:1000 . /app/
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    sqlalchemy \
    psycopg2-binary \
    bcrypt \
    python-jose[cryptography] \
    python-multipart \
    celery[redis] \
    redis \
    openpyxl \
    paramiko \
    requests \
    pydantic-settings \
    google-genai
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
