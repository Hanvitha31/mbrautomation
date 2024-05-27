import boto3
import pandas as pd
import io
from datetime import datetime, timedelta
from pptx import Presentation
from pptx.util import Pt
from pptx.enum.shapes import MSO_SHAPE
from pptx.util import Inches
from pptx.dml.color import RGBColor

# Initialize AWS clients
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
iam = boto3.client('iam')
rds = boto3.client('rds')
cloudwatch = boto3.client('cloudwatch')
acm = boto3.client('acm')
ce_client = boto3.client('ce')
savingsplans = boto3.client('savingsplans')


# S3 bucket name
bucket_name = 'govardhanicici'  # Update with your S3 bucket name

def get_users_without_access_key():
    iam = boto3.client('iam')
    response = iam.list_users()
    users_without_access_key = []

    for user in response['Users']:
        user_name = user['UserName']
        # Check if the user has any access keys
        access_keys = iam.list_access_keys(UserName=user_name)
        if not access_keys['AccessKeyMetadata']:
            users_without_access_key.append(user_name)

    return users_without_access_key

def is_mfa_enabled(user_name):
    try:
        iam = boto3.client('iam')
        mfa_status = iam.list_mfa_devices(UserName=user_name)
        if not mfa_status['MFADevices']:
            return 'disabled'
        return 'enabled'  # Just in case you need to distinguish enabled users
    except Exception as e:
        print(f"Error retrieving MFA status for user {user_name}: {e}")
        return 'unknown'

def get_mfa_enabled_console_users():
    users_without_access_key = get_users_without_access_key()
    users_without_mfa = [(user, is_mfa_enabled(user)) for user in users_without_access_key]

    # Create a DataFrame
    df = pd.DataFrame(users_without_mfa, columns=['User', 'MFA_STATUS'])
    return df

def get_inactive_users(threshold_days=90):
    inactive_users = []
    active_users = []
    response = iam.list_users()

    # Iterate through each user
    for user in response['Users']:
        user_name = user['UserName']

        # Get a list of access keys for the user
        access_keys = iam.list_access_keys(UserName=user_name)

        # Check each access key for last usage
        is_inactive = True
        for key in access_keys['AccessKeyMetadata']:
            access_key_id = key['AccessKeyId']
            # Get last usage information for the access key
            last_used_response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_time = last_used_response['AccessKeyLastUsed'].get('LastUsedDate')

            # Check if access key has never been used or last used more than threshold_days ago
            if last_used_time is None or (datetime.now() - last_used_time.replace(tzinfo=None)) <= timedelta(days=threshold_days):
                is_inactive = False
                break

        if is_inactive:
            inactive_users.append({'User Name': user_name})
        else:
            active_users.append({'User Name': user_name})

    # Combine active and inactive users into a single DataFrame
    inactive_users_df = pd.DataFrame(inactive_users)
    active_users_df = pd.DataFrame(active_users)
    return pd.concat([inactive_users_df, active_users_df], keys=['Inactive Users', 'Active Users'])

def get_security_group_details():
    response = ec2.describe_security_groups()
    sg_data = []
    for sg in response['SecurityGroups']:
        for rule in sg['IpPermissions']:
            if 'FromPort' in rule and rule['FromPort'] not in [80, 443]:
                is_all_traffic = False
                source = ""
                if 'IpRanges' in rule:
                    for ip_range in rule['IpRanges']:
                        if ip_range['CidrIp'] == '0.0.0.0/0' or ip_range['CidrIp'] == '::/0':
                            is_all_traffic = True
                            source = "All Traffic"
                            break
                if 'UserIdGroupPairs' in rule:
                    for pair in rule['UserIdGroupPairs']:
                        if pair['GroupId'] == '0.0.0.0/0' or pair['GroupId'] == '::/0':
                            is_all_traffic = True
                            source = "All Traffic"
                            break
                if is_all_traffic:
                    sg_name = sg['GroupName']
                    sg_id = sg['GroupId']
                    port = rule['FromPort']
                    port_text = 'all port' if port in [0, -1] else str(port)
                    sg_data.append([sg_name, sg_id, port_text, source])
    return pd.DataFrame(sg_data, columns=['Security Group Name', 'Security Group ID', 'Port', 'Source'])

def get_available_volumes():
    response = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    volumes = response['Volumes']
    volume_data = [[vol['VolumeId'], vol['Size'], vol['State']] for vol in volumes]
    return pd.DataFrame(volume_data, columns=['Volume ID', 'Size (GB)', 'State'])

def get_unencrypted_volumes():
    response = ec2.describe_volumes()
    unencrypted_volumes = []

    for volume in response['Volumes']:
        if not volume['Encrypted']:
            unencrypted_volumes.append([
                volume['VolumeId'],
                volume['Size'],
                volume['VolumeType'],
                'Unencrypted'
            ])

    return pd.DataFrame(unencrypted_volumes, columns=['Volume ID', 'Size (GiB)', 'Volume Type', 'Encryption Status'])

def fetch_unassociated_ips():
    ec2 = boto3.client('ec2')
    response = ec2.describe_addresses()
    addresses = response['Addresses']

    ip_data = [
        {"Allocation ID": addr["AllocationId"], "Public IP": addr["PublicIp"]}
        for addr in addresses
        if "AssociationId" not in addr
    ]

    unassociated_ips_df = pd.DataFrame(ip_data)

    # Reset the index to get the expected 0-based index
    unassociated_ips_df.reset_index(drop=True, inplace=True)

    return unassociated_ips_df

# Function to get EC2 instance utilization data
def get_ec2_instance_utilization():
    utilization_data = []
    reservations = ec2.describe_instances()['Reservations']
    for reservation in reservations:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            status_check = ec2.describe_instance_status(InstanceIds=[instance_id])
            if status_check['InstanceStatuses']:
                instance_status = status_check['InstanceStatuses'][0]['InstanceStatus']['Status']
                system_status = status_check['InstanceStatuses'][0]['SystemStatus']['Status']
            else:
                instance_status = 'Unknown'
                system_status = 'Unknown'

            # Query CPU utilization metric data
            cpu_metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'cpu_utilization',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2',
                                'MetricName': 'CPUUtilization',
                                'Dimensions': [
                                    {'Name': 'InstanceId', 'Value': instance_id}
                                ]
                            },
                            'Period': 3600,
                            'Stat': 'Average',
                            'Unit': 'Percent'
                        },
                        'ReturnData': True
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(days=1),
                EndTime=datetime.utcnow()
            )
            cpu_utilization = cpu_metric_data['MetricDataResults'][0]['Values']
            avg_cpu_utilization = sum(cpu_utilization) / len(cpu_utilization) if cpu_utilization else None

            # Query disk utilization metric data
            disk_metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'disk_utilization',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2',
                                'MetricName': 'DiskSpaceUtilization',
                                'Dimensions': [
                                    {'Name': 'InstanceId', 'Value': instance_id}
                                ]
                            },
                            'Period': 3600,
                            'Stat': 'Average',
                            'Unit': 'Percent'
                        },
                        'ReturnData': True
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(days=1),
                EndTime=datetime.utcnow()
            )
            disk_utilization = disk_metric_data['MetricDataResults'][0]['Values']
            avg_disk_utilization = sum(disk_utilization) / len(disk_utilization) if disk_utilization else None

            # Query memory utilization metric data
            memory_metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'memory_utilization',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2',
                                'MetricName': 'MemoryUtilization',
                                'Dimensions': [
                                    {'Name': 'InstanceId', 'Value': instance_id}
                                ]
                            },
                            'Period': 3600,
                            'Stat': 'Average',
                            'Unit': 'Percent'
                        },
                        'ReturnData': True
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(days=1),
                EndTime=datetime.utcnow()
            )
            memory_utilization = memory_metric_data['MetricDataResults'][0]['Values']
            avg_memory_utilization = sum(memory_utilization) / len(memory_utilization) if memory_utilization else None

            # Add data to the list
            utilization_data.append([
                instance_id, instance_status, system_status,
                avg_cpu_utilization, avg_disk_utilization, avg_memory_utilization
            ])

    # Create a DataFrame and return it
    columns = ['Instance ID', 'Instance Status', 'System Status', 'Avg CPU Utilization (%)', 'Avg Disk Utilization (%)', 'Avg Memory Utilization (%)']
    return pd.DataFrame(utilization_data, columns=columns)


# Function to check engine end-of-life status (Dummy function, replace with actual logic)
def check_engine_end_of_life(engine, engine_version):
    # Dummy implementation, replace with actual end-of-life checking logic
    return "No"

def get_rds_utilization(threshold=90):
    try:
        instances = rds.describe_db_instances()['DBInstances']
        utilization_data = []
        for instance in instances:
            instance_id = instance['DBInstanceIdentifier']
            # Query CPU utilization metric data
            metrics = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'cpu_query',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/RDS',
                                'MetricName': 'CPUUtilization',
                                'Dimensions': [
                                    {'Name': 'DBInstanceIdentifier', 'Value': instance_id}
                                ]
                            },
                            'Period': 3600,
                            'Stat': 'Average',
                            'Unit': 'Percent'
                        },
                        'ReturnData': True
                    },
                    {
                        'Id': 'freeable_memory_query',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/RDS',
                                'MetricName': 'FreeableMemory',
                                'Dimensions': [
                                    {'Name': 'DBInstanceIdentifier', 'Value': instance_id}
                                ]
                            },
                            'Period': 3600,
                            'Stat': 'Average',
                            'Unit': 'Bytes'
                        },
                        'ReturnData': True
                    },
                    {
                        'Id': 'free_storage_space_query',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/RDS',
                                'MetricName': 'FreeStorageSpace',
                                'Dimensions': [
                                    {'Name': 'DBInstanceIdentifier', 'Value': instance_id}
                                ]
                            },
                            'Period': 3600,
                            'Stat': 'Average',
                            'Unit': 'Bytes'
                        },
                        'ReturnData': True
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(days=1),  # Adjust time period if needed
                EndTime=datetime.utcnow()
            )
            # Process metric data
            cpu_utilization = metrics['MetricDataResults'][0]['Values']
            avg_cpu_utilization = sum(cpu_utilization) / len(cpu_utilization) if cpu_utilization else None
            freeable_memory = metrics['MetricDataResults'][1]['Values']
            avg_freeable_memory = sum(freeable_memory) / len(freeable_memory) if freeable_memory else None
            free_storage_space = metrics['MetricDataResults'][2]['Values']
            avg_free_storage_space = sum(free_storage_space) / len(free_storage_space) if free_storage_space else None
            # Convert memory and storage to GB
            avg_freeable_memory_gb = avg_freeable_memory / (1024 ** 3) if avg_freeable_memory else None
            avg_free_storage_space_gb = avg_free_storage_space / (1024 ** 3) if avg_free_storage_space else None
            utilization_data.append([instance_id, avg_cpu_utilization, avg_freeable_memory_gb, avg_free_storage_space_gb])
            # Check if CPU utilization exceeds the threshold
            if avg_cpu_utilization is not None and avg_cpu_utilization > threshold:
                print(f"Instance {instance_id} has CPU utilization above {threshold}%.")
        return pd.DataFrame(utilization_data, columns=['Instance ID', 'Average CPU Utilization (%)', 'Average Freeable Memory (GB)', 'Average Free Storage Space (GB)'])
    except Exception as e:
        print(f"An error occurred in get_rds_utilization: {e}")
        raise e


# Function to get RDS engine versions and end-of-life status
def get_rds_engine_versions():
    instances = rds.describe_db_instances()['DBInstances']
    engine_data = []
    for instance in instances:
        instance_id = instance['DBInstanceIdentifier']
        engine = instance['Engine']
        engine_version = instance['EngineVersion']
        # Check engine end-of-life status
        end_of_life = check_engine_end_of_life(engine, engine_version)
        # Fetch certificate details
        certificate_info = rds.describe_certificates(CertificateIdentifier=instance['CACertificateIdentifier'])
        certificate_expiry = certificate_info['Certificates'][0]['ValidTill'].strftime('%Y-%m-%d')
        # Get RDS status and storage auto-scaling status
        status = instance['DBInstanceStatus']
        auto_scaling_enabled = 'Enabled' if instance.get('StorageAutoscaling') else 'Disabled'
        engine_data.append([instance_id, engine, engine_version, end_of_life, certificate_expiry, status, auto_scaling_enabled])
    return pd.DataFrame(engine_data, columns=['Instance ID', 'Engine', 'Engine Version', 'End of Life', 'DB Instance Certificate Expiration Date', 'Status', 'Storage Auto-Scaling Enabled'])

def get_ec2_reservations():
    try:
        reservations = ec2.describe_reserved_instances()['ReservedInstances']
        reservations_data = []
        for reservation in reservations:
            if reservation['State'] != 'active':
                continue
            reservation_id = reservation['ReservedInstancesId']
            instance_type = reservation['InstanceType']
            end = reservation['End']
            instance_count = reservation['InstanceCount']
            payment_option = reservation['UsagePrice']
            offering_class = reservation['OfferingClass']
            scope = reservation['Scope']
            platform = reservation['ProductDescription']
            reservations_data.append([reservation_id, instance_type, end.strftime('%Y-%m-%d'), instance_count, payment_option, offering_class, scope, platform])
        return pd.DataFrame(reservations_data, columns=['Reservation ID', 'Instance Type', 'Expiry Date', 'Instance Count', 'Payment Option', 'Offering Class', 'Scope', 'Platform'])
    except Exception as e:
        print(f"An error occurred in get_ec2_reservations: {e}")
        raise e

def get_savings_plans():
    try:
        savings_plans = savingsplans.describe_savings_plans()
        plans_data = []
        for plan in savings_plans['savingsPlans']:
            plan_id = plan['savingsPlanId']
            plan_type = plan['savingsPlanType']
            instance_family = plan['instanceFamily']
            region = plan['region']
            end = plan['end']
            plans_data.append([plan_id, plan_type, instance_family, region, end])
        return pd.DataFrame(plans_data, columns=['Plan ID', 'Plan Type', 'Instance Family', 'Region', 'End Date'])
    except Exception as e:
        print(f"An error occurred in get_savings_plans: {e}")
        raise e

def get_rds_reservations():
    try:
        reservations = rds.describe_reserved_db_instances()['ReservedDBInstances']
        reservations_data = []
        for reservation in reservations:
            if reservation['State'] != 'active':
                continue
            reservation_id = reservation['ReservedDBInstanceId']
            product = reservation['ProductDescription']
            region = reservation['AvailabilityZone']
            instance_class = reservation['DBInstanceClass']
            end_date = reservation['StartTime'] + timedelta(seconds=reservation['Duration'])
            remaining_days = (end_date - datetime.utcnow()).days
            multi_az = reservation['MultiAZ']
            quantity = reservation['DBInstanceCount']
            offering_type = reservation['OfferingType']
            reservations_data.append([
                reservation_id, product, region, instance_class, remaining_days, multi_az, quantity, offering_type
            ])
        return pd.DataFrame(reservations_data, columns=[
            'Reservation ID', 'Product', 'Region', 'Class', 'Remaining Days', 'Multi-AZ', 'Quantity', 'Offering Type'
        ])
    except Exception as e:
        print(f"An error occurred in get_rds_reservations: {e}")
        raise e



def check_acm_expiry():
    # List all certificates in the account
    response = acm.list_certificates()

    # Track ACM data
    acm_data = []

    # Get details for each certificate
    for cert in response['CertificateSummaryList']:
        cert_details = acm.describe_certificate(CertificateArn=cert['CertificateArn'])

        # Check if 'Certificate' key exists in the response
        if 'Certificate' in cert_details:
            expiration_date = cert_details['Certificate'].get('NotAfter')

            # Check if expiration date exists
            if expiration_date:
                expiration_date = expiration_date.replace(tzinfo=None)  # Remove timezone info

                # Check if the certificate is expired or expiring soon (within 30 days)
                if expiration_date < datetime.utcnow():
                    status = "Expired"
                elif (expiration_date - datetime.utcnow()) <= timedelta(days=30):
                    status = "Expiring soon (within 30 days)"
                else:
                    status = "Valid"

                # Extract domain name
                domain_name = cert_details['Certificate'].get('DomainName')

                # Check if domain name exists
                if domain_name:
                    # Append certificate data
                    acm_data.append([cert_details['Certificate']['CertificateArn'], domain_name, expiration_date, status])
                else:
                    # Append certificate data with no domain name
                    acm_data.append([cert_details['Certificate']['CertificateArn'], None, expiration_date, "No domain name"])
            else:
                # Append certificate data with no expiration date
                acm_data.append([cert_details['Certificate']['CertificateArn'], domain_name, None, "No expiration date"])
        else:
            # Append certificate data with failed status domain verification
            acm_data.append([cert['CertificateArn'], None, None, "Failed domain verification"])

    # Create a DataFrame and return it
    return pd.DataFrame(acm_data, columns=['Certificate ARN', 'Domain Name', 'Expiration Date', 'Expiration Status'])

def check_budget_alarms():
    # Create a boto3 client for the AWS Budgets service
    budgets_client = boto3.client('budgets')

    # Retrieve the account ID
    account_id = boto3.client('sts').get_caller_identity()['Account']

    # Describe budgets for the account
    response = budgets_client.describe_budgets(AccountId=account_id)
    budgets = response.get('Budgets', [])

    if budgets:
        # If there are budgets, return a DataFrame with budget names and their status as 'Set'
        return pd.DataFrame([[budget['BudgetName'], 'Set'] for budget in budgets], columns=['Budget Name', 'Status'])
    else:
        # If no budgets are found, return a DataFrame indicating no budget alarms are set
        return pd.DataFrame([['No Budget Alarms', 'Not Set']], columns=['Budget Name', 'Status'])


def get_ec2_termination_protection():
    # Retrieve the termination protection information for each EC2 instance
    response = ec2.describe_instances()
    instance_data = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_state = instance['State']['Name']
            termination_protection = instance.get('InstanceLifecycle') == 'spot' or instance.get('InstanceLifecycle') == 'scheduled'
            instance_data.append([instance_id, instance_state, 'Yes' if termination_protection else 'No'])
    return pd.DataFrame(instance_data, columns=['Instance ID', 'Instance State', 'Termination Protection'])

def save_data_to_ppt(dataframes: list, function_names: list, logo_path: str, first_slide_image_path: str):
    # Create a PowerPoint presentation
    prs = Presentation()

    # Add the first slide with the specific image
    first_slide_layout = prs.slide_layouts[6]  # Use a blank layout
    first_slide = prs.slides.add_slide(first_slide_layout)

    # Add the specific image to the first slide
    first_slide_width = prs.slide_width
    first_slide_height = prs.slide_height
    first_slide.shapes.add_picture(first_slide_image_path, 0, 0, width=first_slide_width, height=first_slide_height)

    # Prompt for the input string
    name = input("Enter the name: ")

    # Add the name to the first slide
    left = Inches(1)
    top = Inches(5)
    width = Inches(8)
    height = Inches(1)
    text_box = first_slide.shapes.add_textbox(left, top, width, height)
    text_frame = text_box.text_frame
    text_frame.text = name
    for paragraph in text_frame.paragraphs:
        for run in paragraph.runs:
            run.font.size = Pt(24)
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)  # White font color


    # Add the date of execution
    execution_date = datetime.now().strftime("%Y-%m-%d")
    p = text_frame.add_paragraph()
    p.text = execution_date
    for run in p.runs:
        run.font.size = Pt(18)
        run.font.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)  # White font color


    # Iterate over each DataFrame and its corresponding function name for the remaining slides
    for dataframe, function_name in zip(dataframes, function_names):
        # Add a new slide
        slide_layout = prs.slide_layouts[5]  # Use a layout with title and content
        slide = prs.slides.add_slide(slide_layout)
        title = slide.shapes.title
        title.text = function_name
        title.text_frame.paragraphs[0].font.size = Pt(24)  # Set font size for title to 24

        # Add the logo to the slide
        logo_width = Inches(1.5)
        logo_height = Inches(1.5)
        left = Inches(0.3)  # Position logo 0.3 inch from the left edge
        top = Inches(0.3)  # Position logo 0.3 inch from the top edge
        slide.shapes.add_picture(logo_path, left, top, width=logo_width, height=logo_height)

        left = Inches(1.5)  # Adjust this value based on your table width
        top = Inches(1.2)
        width = Inches(8)
        height = Inches(5)
        table = slide.shapes.add_table(dataframe.shape[0] + 1, dataframe.shape[1], left, top, width, height).table

        # Set font size to 12 for the table text
        for cell in table.iter_cells():
            for paragraph in cell.text_frame.paragraphs:
                for run in paragraph.runs:
                    run.font.size = Pt(12)

        # Add column headers
        for col_index, column_name in enumerate(dataframe.columns):
            table.cell(0, col_index).text = column_name

        # Add data to the table
        for row_index, row in enumerate(dataframe.itertuples(), start=1):
            for col_index, value in enumerate(row[1:], start=0):
                table.cell(row_index, col_index).text = str(value)

    # Save the presentation to a buffer
    ppt_buffer = io.BytesIO()
    prs.save(ppt_buffer)
    ppt_buffer.seek(0)

    # Upload PowerPoint file to S3
    s3 = boto3.client('s3')
    s3.put_object(Bucket=bucket_name, Key='aws_data.pptx', Body=ppt_buffer)
    print('aws_data.pptx has been saved to S3 bucket "{}".'.format(bucket_name))


def lambda_handler():
    # Get data from different functions
    dataframes = [
        get_mfa_enabled_console_users(),
        get_inactive_users(),
        get_security_group_details(),
        get_available_volumes(),
        get_unencrypted_volumes(),
        fetch_unassociated_ips(),
        get_ec2_instance_utilization(),
        get_rds_engine_versions(),
        get_rds_utilization(),
        get_ec2_reservations(),
        get_savings_plans(),
        get_rds_reservations(),
        check_acm_expiry(),
        check_budget_alarms(),
        get_ec2_termination_protection(),
    ]


    # Path to the Cloud4C logo
    logo_path = '/root/c4c.jpg'  # Update with the actual path to the logo on your server
    # Path to the specific image for the first slide
    first_slide_image_path = '/root/c4c1.jpg'  # Update with the actual path to the image on your server

    # Save combined data to a PowerPoint presentation
    save_data_to_ppt(dataframes, [
        'Console users without MFA',
        'Inactive Users',
        'Security groups',
        'Available Volumes',
        'Unencrypted Volumes',
        'Unassociated IP',
        'EC2 Instance Utilization',
        'RDS Details',
        'RDS Utilization',
        'EC2 Reservations',
        'Saving Plans',
        'RDS Reservations',
        'ACM',
        'Budget alarms',
        'EC2 Termination Protection',
      ], logo_path, first_slide_image_path)

    return {
        'statusCode': 200,
        'body': 'Data has been saved to an AWS PowerPoint presentation.'
    }

lambda_handler()