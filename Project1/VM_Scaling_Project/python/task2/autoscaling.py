
from tracemalloc import Statistic
from typing import Protocol
from urllib import response
import boto3
import botocore
import os
from numpy import average
import requests
import time
import json
import re

from torch import threshold

########################################
# Constants
########################################
with open('auto-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']
LAUNCH_CONFIGURATION_NAME = configuration['launch_configuration_name']
AUTO_SCALING_TARGET_GROUP = configuration['auto_scaling_target_group']
LOAD_BALANCER_NAME = configuration['load_balancer_name']
AUTO_SCALING_GROUP_NAME = configuration['auto_scaling_group_name']
SUBMISSION_USERNAME = os.environ['SUBMISSION_USERNAME']
SUBMISSION_PASSWORD = os.environ['SUBMISSION_PASSWORD']

########################################
# Tags
########################################
tag_pairs = [
    ("Project", "vm-scaling"),
]
TAGS = [{'Key': k, 'Value': v} for k, v in tag_pairs]

TEST_NAME_REGEX = r'name=(.*log)'

########################################
# Utility functions
########################################


def create_instance(ami, sg_name):
    """
    Given AMI, create and return an AWS EC2 instance object
    :param ami: AMI image name to launch the instance with
    :param sg_name: id of the security group to be attached to instance
    :return: instance object
    """

    # TODO: Create an EC2 instance
    # decalare ec2:
    ec2 = boto3.resource('ec2', region_name= "us-east-1")
    instance = ec2.create_instances(
        ImageId = ami,
        InstanceType = INSTANCE_TYPE,
        MinCount = 1,
        MaxCount = 1,
        SecurityGroupIds = [sg_name],
        TagSpecifications = [{
            'ResourceType':'instance',
            'Tags': TAGS
        }]
    )[0]
    # since the dns name is not available until the running state,
    # so use wait_until_running
    instance.wait_until_running()
    instance.load()
    return instance


def initialize_test(load_generator_dns, first_web_service_dns):
    """
    Start the auto scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/autoscaling?dns={}'.format(
        load_generator_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 

    # TODO: return log File name
    return get_test_id(response)


def initialize_warmup(load_generator_dns, load_balancer_dns):
    """
    Start the warmup test
    :param lg_dns: Load Generator DNS
    :param load_balancer_dns: Load Balancer DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/warmup?dns={}'.format(
        load_generator_dns, load_balancer_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass  

    # TODO: return log File name
    return get_test_id(response)


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]

def check_running_instances():
    ec2 = boto3.resource('ec2', region_name='us-east-1')
    ls_running_instances = []
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for instance in instances:
        ls_running_instances.append(instance.id)
    return ls_running_instances

def terminate_instances(ls_running_instances):
    ec2 = boto3.resource('ec2', region_name='us-east-1')
    ec2.instances.filter(InstanceIds=ls_running_instances).terminate()
def destroy_asg():
    client = boto3.client("autoscaling", region_name= "us-east-1")
    response = client.delete_auto_scaling_group(
        AutoScalingGroupName = AUTO_SCALING_GROUP_NAME,
    )
def destroy_load_balancer(lb_arn):
    client = boto3.client('elbv2', region_name= "us-east-1")
    response = client.delete_load_balancer(
        LoadBalancerArn = lb_arn
    )
def destroy_target_groups(tg_arn):
    client = boto3.client('elbv2', region_name= "us-east-1")
    response = client.delete_target_group(
        TargetGroupArn = tg_arn
    )
def destroy_launch_config():
    client = boto3.client("autoscaling", region_name= "us-east-1")
    response = client.delete_launch_configuration(
        LaunchConfigurationName = LAUNCH_CONFIGURATION_NAME
    )
def desotry_security_group():
    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup('id')
    security_group.delete(
        GroupName = "Load Generator HTTP Sec Group"
    )
    security_group.delete(
        GroupName = "ASG ELP Sec Group"
    )
def destroy_resources(lb_arn, tg_arn):
    """
    Delete all resources created for this task
    :param msg: message
    :return: None
    """
    # TODO: implement this method
    # delete asg
    destroy_asg()
    # delete load balancer
    destroy_load_balancer(lb_arn)
    # delete launch configuration
    destroy_launch_config()
    # delete target groups
    destroy_target_groups(tg_arn)
    # delete security groups
    desotry_security_group()
    # terminate all intances
    terminate_instances(check_running_instances)


def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def is_test_complete(load_generator_dns, log_name):
    """
    Check if auto scaling test is complete
    :param load_generator_dns: lg dns
    :param log_name: log file name
    :return: True if Auto Scaling test is complete and False otherwise.
    """
    log_string = 'http://{}/log?name={}'.format(load_generator_dns, log_name)

    # creates a log file for submission and monitoring
    f = open(log_name + ".log", "w")
    log_text = requests.get(log_string).text
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text


def authenticate(load_generator_dns, submission_password, submission_username):
    """
    Authentication on LG
    :param load_generator_dns: LG DNS
    :param submission_password: SUBMISSION_PASSWORD
    :param submission_username: SUBMISSION_USERNAME
    :return: None
    """
    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        load_generator_dns, submission_password, submission_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass

def create_security_group(group_name, group_description, sg_permissions):
    ec2 = boto3.client('ec2', region_name="us-east-1")
    for security_group_names in ec2.describe_security_groups()['SecurityGroups']:
        if security_group_names['GroupName'] == group_name:
            return (security_group_names['GroupId'])
    response = ec2.describe_vpcs()
    vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')
    try:
        response = ec2.create_security_group(
            GroupName = group_name,
            Description = group_description,
            TagSpecifications = [{
                'ResourceType': 'security-group',
                'Tags' : TAGS
            }]
        )
        security_group_id = response['GroupId']
        print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))
        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions = sg_permissions
        )
        print('Ingress Successfully Set %s' % data)
        return security_group_id
    except botocore.exceptions.ClientError as e:
        print(e)

def create_ASG_launch_config(name, sg2_id):
    # TODO: do I need to check if the config name exists?
    client = boto3.client('autoscaling', region_name='us-east-1')
    for launch_config_names in client.describe_launch_configurations()["LaunchConfigurations"]:
        if launch_config_names["LaunchConfigurationName"] == name:
            return client.describe_launch_configurations(
                LaunchConfigurationNames = [name,]
            )
    response = client.create_launch_configuration(
        LaunchConfigurationName = name,
        ImageId = WEB_SERVICE_AMI,
        InstanceType = INSTANCE_TYPE,
        InstanceMonitoring = {
            'Enabled' : True
        },
        SecurityGroups = [
            sg2_id
        ]
    )
    return response
def create_ELB_target_group(name):
    client = boto3.client('elbv2', region_name= "us-east-1")
    for target_group_names in client.describe_target_groups()["TargetGroups"]:
        if target_group_names["TargetGroupName"] == name:
            return client.describe_target_groups(
                Names = [name,]
            )
    response = client.create_target_group(
        Name = name,
        Protocol = 'HTTP',
        Port = 80,
        VpcId = "vpc-07e6258943f9370d7",
        HealthCheckProtocol = 'HTTP',
        HealthCheckPath = '/',
        TargetType = 'instance',
        Tags = TAGS
    )
    return response
def create_application_load_balancer(name, sg_id):
    client = boto3.client('elbv2', region_name= "us-east-1")
    for load_balancer_names in client.describe_load_balancers()["LoadBalancers"]:
        if load_balancer_names["LoadBalancerName"] == name:
            return client.describe_load_balancers(
                Names = [name,]
            )
    response = client.create_load_balancer(
        Name = name,
        Subnets = [
            'subnet-0ae3c6149e1297348',
            'subnet-08703db50ddd656bb',
            'subnet-0efab80f12131f711',
            'subnet-0bf6866eaa99e6bbf',
            'subnet-0d671428924afda55',
            'subnet-02c4f40723c00bc92'
        ],
        SecurityGroups = [sg_id],
        Tags = TAGS,
        Type = 'application'
    )
    waiter = client.get_waiter("load_balancer_available")
    waiter.wait(
        LoadBalancerArns = [response["LoadBalancers"][0]["LoadBalancerArn"]]
    )
    response = client.describe_load_balancers(
        LoadBalancerArns = [response["LoadBalancers"][0]["LoadBalancerArn"]]
    )
    return response

def associate_target_load_balancer(lb_arn, tg_arn):
    client = boto3.client('elbv2', region_name= "us-east-1")
    response = client.create_listener(
        LoadBalancerArn = lb_arn,
        Protocol = 'HTTP',
        Port = 80,
        DefaultActions=[
            {
                'Type' : 'forward',
                'TargetGroupArn' : tg_arn
            }
        ],
        Tags=TAGS
    )
    return response
def create_ASG(name, lau_config, tg_arn):
    client = boto3.client('autoscaling', region_name= "us-east-1")
    for auto_scaling_names in client.describe_auto_scaling_groups()["AutoScalingGroups"]:
        if auto_scaling_names["AutoScalingGroupName"] == name:
            return client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[name,]
            )
    response = client.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchConfigurationName = lau_config,
        MinSize = configuration['asg_min_size'],
        MaxSize = configuration['asg_max_size'],
        # DesiredCapacity = 1,
        HealthCheckType = 'EC2',
        HealthCheckGracePeriod = configuration['health_check_grace_period'],
        DefaultCooldown = configuration['asg_default_cool_down_period'],
        # VPCZoneIdentifier = 'subnet-0ae3c6149e1297348',
        AvailabilityZones = [
            'us-east-1b',
            'us-east-1e',
            'us-east-1c',
            'us-east-1d',
            'us-east-1a',
            'us-east-1f'
        ],
        TargetGroupARNs = [tg_arn],
        Tags=TAGS
    )
    return response

def create_attach_policy_scale_in(asg_name):
    client = boto3.client('autoscaling', region_name= "us-east-1")
    response = client.put_scaling_policy(
        AutoScalingGroupName = asg_name,
        PolicyName = "P1-ASG-Scale-In-Policy",
        PolicyType = "SimpleScaling",
        AdjustmentType = "ChangeInCapacity",
        ScalingAdjustment = configuration["scale_in_adjustment"],
        Cooldown = configuration["cool_down_period_scale_in"],
    )
    return response
def associate_cloudwatch_scale_in(alrm_name, scale_in_arn):
    client = boto3.client('cloudwatch', region_name= "us-east-1")
    response = client.put_metric_alarm(
        AlarmName = alrm_name,
        AlarmDescription = "Cloudwatch for scale in",
        AlarmActions = [scale_in_arn],
        MetricName = "CPUUtilization",
        Namespace = "AWS/EC2",
        Statistic = "Average",
        Unit = "Percent",
        Dimensions = [
            {
                "Name" : "AutoScalingGroupName",
                "Value" : configuration["auto_scaling_group_name"]
            }
        ],
        Period = configuration["alarm_period"],
        EvaluationPeriods = configuration["alarm_evaluation_periods_scale_in"],
        Threshold = configuration["cpu_lower_threshold"],
        ComparisonOperator = "LessThanThreshold",
        Tags = TAGS
    )

def create_attach_policy_scale_out(asg_name):
    client = boto3.client('autoscaling', region_name= "us-east-1")
    response = client.put_scaling_policy(
        AutoScalingGroupName = asg_name,
        PolicyName = "P1-ASG-Scale-Out-Policy",
        PolicyType = "SimpleScaling",
        AdjustmentType = "ChangeInCapacity",
        ScalingAdjustment = configuration["scale_out_adjustment"],
        Cooldown = configuration["cool_down_period_scale_out"],
    )
    return response

def associate_cloudwatch_scale_out(alrm_name, scale_out_arn):
    client = boto3.client('cloudwatch', region_name= "us-east-1")
    response = client.put_metric_alarm(
        AlarmName = alrm_name,
        AlarmDescription = "Cloudwatch for scale in",
        AlarmActions = [scale_out_arn],
        MetricName = "CPUUtilization",
        Namespace = "AWS/EC2",
        Statistic = "Average",
        Unit = "Percent",
        Dimensions = [
            {
                "Name" : "AutoScalingGroupName",
                "Value" : configuration["auto_scaling_group_name"]
            }
        ],
        Period = configuration["alarm_period"],
        EvaluationPeriods = configuration["alarm_evaluation_periods_scale_out"],
        Threshold = configuration["cpu_upper_threshold"],
        ComparisonOperator = "GreaterThanOrEqualToThreshold",
        Tags = TAGS
    )

########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Programmatically provision autoscaling resources
    #   - Create security groups for Load Generator and ASG, ELB
    #   - Provision a Load Generator
    #   - Generate a Launch Configuration
    #   - Create a Target Group
    #   - Provision a Load Balancer
    #   - Associate Target Group with Load Balancer
    #   - Create an Autoscaling Group
    #   - Initialize Warmup Test
    #   - Initialize Autoscaling Test
    #   - Terminate Resources

    print_section('1 - create two security groups')

    PERMISSIONS = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # TODO: create two separate security groups and obtain the group ids
    sg1_id = create_security_group(
        "Load Generator HTTP Sec Group", 
        "Permissions for load generator",
        PERMISSIONS
    )  # Security group for Load Generator instances
    sg2_id = create_security_group(
        "ASG ELP Sec Group",
        "Permissions for ASG and ELB",
        PERMISSIONS
    )  # Security group for ASG, ELB instances
    print("sg1 id", sg1_id)
    print("sg2 id", sg2_id)
    print_section('2 - create LG')

    # TODO: Create Load Generator instance and obtain ID and DNS
    ec2 = boto3.resource('ec2',region_name='us-east-1')
    lg = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    lg_id = lg.instance_id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Create LC (Launch Config)')
    # TODO: create launch configuration
    lau_config = create_ASG_launch_config(LAUNCH_CONFIGURATION_NAME, sg2_id)

    print_section('4. Create TG (Target Group)')
    # TODO: create Target Group
    tg_arn = create_ELB_target_group(AUTO_SCALING_TARGET_GROUP)['TargetGroups'][0]['TargetGroupArn']
    print_section('5. Create ELB (Elastic/Application Load Balancer)')

    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    lb = create_application_load_balancer(LOAD_BALANCER_NAME, sg2_id)
    lb_arn = lb["LoadBalancers"][0]["LoadBalancerArn"]
    lb_dns = lb["LoadBalancers"][0]["DNSName"]
    print("lb started. ARN={}, DNS={}".format(lb_arn, lb_dns))

    print_section('6. Associate ELB with target group')
    # TODO Associate ELB with target group
    listener = associate_target_load_balancer(lb_arn, tg_arn)

    print_section('7. Create ASG (Auto Scaling Group)')
    # TODO create Autoscaling group
    asg = create_ASG(AUTO_SCALING_GROUP_NAME, LAUNCH_CONFIGURATION_NAME, tg_arn)
    print_section('8. Create policy and attached to ASG')
    # TODO Create Simple Scaling Policies for ASG
    scale_in = create_attach_policy_scale_in(AUTO_SCALING_GROUP_NAME)
    scale_out = create_attach_policy_scale_out(AUTO_SCALING_GROUP_NAME)

    print_section('9. Create Cloud Watch alarm. Action is to invoke policy.')
    # TODO create CloudWatch Alarms and link Alarms to scaling policies
    # cw_scale_in = associate_cloudwatch_scale_in(scale_in["Alarms"][0]["AlarmName"])
    # cw_scale_out = associate_cloudwatch_scale_out(scale_out["Alarms"][0]["AlarmName"])
    cw_scale_in = associate_cloudwatch_scale_in("Cloud Watch Scale In", scale_in["PolicyARN"])
    cw_scale_out = associate_cloudwatch_scale_out("Cloud Watch Scale Out", scale_out["PolicyARN"])

    print_section('10. Authenticate with the load generator')
    authenticate(lg_dns, SUBMISSION_PASSWORD, SUBMISSION_USERNAME)

    # print_section('11. Submit ELB DNS to LG, starting warm up test.')
    # warmup_log_name = initialize_warmup(lg_dns, lb_dns)
    # while not is_test_complete(lg_dns, warmup_log_name):
    #     time.sleep(1)

    print_section('12. Submit ELB DNS to LG, starting auto scaling test.')
    # May take a few minutes to start actual test after warm up test finishes
    log_name = initialize_test(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, log_name):
        time.sleep(1)

    destroy_resources(lb_arn, tg_arn)


if __name__ == "__main__":
    main()