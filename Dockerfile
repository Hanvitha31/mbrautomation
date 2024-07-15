# Use the official AWS Lambda Python base image
FROM amazon/aws-sam-cli-build-image-python3.8
# Install the pptx module
RUN pip install python-pptx
RUN pip install pandas
RUN pip install pillow
RUN pip install boto3
# Copy your Lambda function code into the container
COPY lambda_function.py ${LAMBDA_TASK_ROOT}
# Set the CMD to your handler (could also be done as a parameter override outside of the Dockerfile)
CMD ["tail", "-f", "/dev/null" ]
