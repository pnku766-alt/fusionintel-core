FROM python:3.12-slim

WORKDIR /app

# copy project
COPY . /app

# install (api extras)
RUN python -m pip install --upgrade pip \
 && python -m pip install -e ".[api]"

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
