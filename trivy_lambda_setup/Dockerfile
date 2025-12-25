# Trivy Scanner Lambda Container
# Based on AWS Lambda Python runtime with Trivy installed

FROM public.ecr.aws/lambda/python:3.11

# Install Trivy
RUN yum install -y wget tar gzip && \
    wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_Linux-64bit.tar.gz | tar xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    trivy --version && \
    yum clean all

# Create cache directory
RUN mkdir -p /tmp/trivy-cache

# Copy function code
COPY lambda_handler.py ${LAMBDA_TASK_ROOT}

# Set the CMD to your handler
CMD [ "lambda_handler.handler" ]
