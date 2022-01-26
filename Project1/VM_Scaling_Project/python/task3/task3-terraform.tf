###########################################################################
# Template for P2 AWS Autoscaling Test                                  #
# Do not edit the first section                                           #
# Only edit the second section to configure appropriate scaling policies  #
###########################################################################

############################
# FIRST SECTION BEGINS     #
# DO NOT EDIT THIS SECTION #
############################
locals {
  common_tags = {
    Project = "vm-scaling"
  }
  asg_tags = [
    {
      key                 = "Project"
      value               = "vm-scaling"
      propagate_at_launch = true
    }
  ]
}

provider "aws" {
  region = "us-east-1"
}


resource "aws_security_group" "lg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "elb_asg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

######################
# FIRST SECTION ENDS #
######################

############################
# SECOND SECTION BEGINS    #
# PLEASE EDIT THIS SECTION #
############################

# Step 1:
# TODO: Add missing values below
# ================================
resource "aws_launch_configuration" "lc" {
  image_id        = "<AMI_ID>"
  instance_type   = "<INSTANCE_TYPE>"
  security_groups = [aws_security_group.elb_asg.id]
}

# Create an auto scaling group with appropriate parameters
# TODO: fill the missing values per the placeholders
resource "aws_autoscaling_group" "asg" {
  availability_zones        = ["us-east-1a"]
  max_size                  = <MAX_NUM_INSTANCES>
min_size                  = <MIN_NUM_INSTANCES>
desired_capacity          = <DEFAULT_NUM_INSTANCES>
default_cooldown          = <COOLDOWN_PERIOD>
health_check_grace_period = <HEALTHCHECK_PERIOD>
health_check_type         = "<HEALTHCHECK_TYPE>"
launch_configuration      = aws_launch_configuration.lc.name
target_group_arns         = ["<FILL_IN_AFTER_STEP2>"]
tags                      = local.asg_tags
}

# TODO: Create a Load Generator AWS instance with proper tags

# Step 2:
# TODO: Create an Application Load Balancer with appropriate listeners and target groups
# The lb_listener documentation demonstrates how to connect these resources
# Create and attach your subnet to the Application Load Balancer 
#
# https://www.terraform.io/docs/providers/aws/r/lb.html
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet
# https://www.terraform.io/docs/providers/aws/r/lb_listener.html
# https://www.terraform.io/docs/providers/aws/r/lb_target_group.html

# Step 3:
# TODO: Create 2 policies: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# https://www.terraform.io/docs/providers/aws/r/autoscaling_policy.html  

# Step 4:
# TODO: Create 2 cloudwatch alarms: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# Don't forget to trigger the appropriate policy you created above when alarm is raised
# https://www.terraform.io/docs/providers/aws/r/cloudwatch_metric_alarm.html


######################################
# SECOND SECTION ENDS                #
# MAKE SURE YOU COMPLETE ALL 4 STEPS #
######################################
