# Start from the Python image so that we have our Python dependencies
# installed.
FROM python:3.7-slim-buster
COPY . /app
WORKDIR /app
RUN pip install .
