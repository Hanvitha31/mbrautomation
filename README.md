# mbrautomation

Using Datafromes, pptx modules in python, the code is develeoped to work in AWS lambda fucntions.

Services Used: AWS Lambda to trigger the function, AWS S3 to store the generated report, IAM Role based Access for enabling the functionality, AWS Event Bridge to trigger on monthly basis and AWS ECR as a repository for the packaged code.
Costing: Cost of around/ below 1$ USD will be occurring on monthly basis for implementing and maintaining the same.
Access:  IAM role for lambda execution must also have permission for – ReadOnlyAccess at account level, PutObject into specific S3 bucket.
Implementation: The code is packaged into a container image and through ECR pushed into Lambda function. Lambda code is triggered on monthly basis using Event Bridge schedule.
