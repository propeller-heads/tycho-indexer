# Use an official Python runtime as a parent image
FROM --platform=linux/amd64 continuumio/miniconda3:24.4.0-0

# Set the working directory in the container to /app
WORKDIR /app

# Add current directory code to /app in container
ADD ./testing /app/testing
ADD ./tycho_client /app/tycho_client

RUN chmod +x /app/testing/tycho-indexer

# Create a new conda environment and install pip
RUN conda create -n myenv pip python=3.9

# Install any needed packages specified in requirements.txt
RUN echo "source activate myenv" >~/.bashrc
ENV PATH /opt/conda/envs/myenv/bin:$PATH

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2 \
    && apt-get clean

RUN /bin/bash -c "source activate myenv && pip install --no-cache-dir -r testing/requirements.txt && cd /app/tycho_client && pip install -r requirements-docker.txt && cd -"

# Make port 80 available to the world outside this container
EXPOSE 80

# Install the substreams cli
RUN wget -c https://github.com/streamingfast/substreams/releases/download/v1.8.0/substreams_linux_x86_64.tar.gz -O - | tar xzf - substreams
RUN mv substreams /usr/local/bin/substreams && chmod +x /usr/local/bin/substreams

# Run the command to start your application
CMD ["python", "testing/cli.py", "--test_yaml_path", "/app/substreams/my_substream/test_assets.yaml", "--with_binary_logs", "--db_url", "postgres://postgres:mypassword@db:5432"]