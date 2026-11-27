FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY app.py .
RUN apk add --no-cache ca-certificates && update-ca-certificates \
    && addgroup -S app && adduser -S app -G app \
    && mkdir -p /data && chown -R app:app /app /data
USER app
EXPOSE 3000
CMD ["python", "-u", "app.py"]
