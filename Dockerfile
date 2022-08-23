FROM python:3.9
COPY . /app
WORKDIR /app
RUN python3 setup.py install
WORKDIR /app/Jira-Lens
ENTRYPOINT ["python3", "Jira-Lens.py","-u"]
