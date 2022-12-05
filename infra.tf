terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.30"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.4.3"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

locals {
  veeam_aws_instance_ami      = var.veeam_aws_edition == "byol" ? local.veeam_aws_instance_ami_byol : (var.veeam_aws_edition == "free" ? local.veeam_aws_instance_ami_free : local.veeam_aws_instance_ami_paid)
  veeam_aws_instance_ami_free = lookup(var.veeam_aws_free_edition_ami_map, var.aws_region)
  veeam_aws_instance_ami_byol = lookup(var.veeam_aws_byol_edition_ami_map, var.aws_region)
  veeam_aws_instance_ami_paid = lookup(var.veeam_aws_paid_edition_ami_map, var.aws_region)
}

### IAM Resources

data "aws_iam_policy_document" "veeam_aws_instance_role_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "veeam_aws_instance_role_inline_policy" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "veeam_aws_instance_role" {
  name               = "veeam-aws-instance-role"
  assume_role_policy = data.aws_iam_policy_document.veeam_aws_instance_role_assume_policy.json

  inline_policy {
    name   = "veeam-aws-instance-policy"
    policy = data.aws_iam_policy_document.veeam_aws_instance_role_inline_policy.json
  }
}

resource "aws_iam_instance_profile" "veeam_aws_instance_profile" {
  name = "veeam-aws-instance-profile"
  role = aws_iam_role.veeam_aws_instance_role.name
}

data "aws_iam_policy_document" "veeam_aws_default_role_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.veeam_aws_instance_role.arn]
    }
  }
}

resource "aws_iam_role" "veeam_aws_default_role" {
  name               = "veeam-aws-default-role"
  assume_role_policy = data.aws_iam_policy_document.veeam_aws_default_role_assume_policy.json
}

resource "aws_iam_policy" "veeam_aws_service_policy" {
  name        = "veeam-aws-service-policy"
  description = "Veeam Backup for AWS permissions to launch worker instances to perform backup and restore operations."

  policy = file("veeam-aws-service-policy.json")
}

resource "aws_iam_role_policy_attachment" "veeam_aws_service_policy_attachment" {
  role       = aws_iam_role.veeam_aws_default_role.name
  policy_arn = aws_iam_policy.veeam_aws_service_policy.arn
}

resource "aws_iam_policy" "veeam_aws_repository_policy" {
  name        = "veeam-aws-repository-policy"
  description = "Veeam Backup for AWS permissions to create backup repositories in an Amazon S3 bucket and to access the repository when performing backup and restore operations."

  policy = file("veeam-aws-repository-policy.json")
}

resource "aws_iam_role_policy_attachment" "veeam_aws_repository_policy_attachment" {
  role       = aws_iam_role.veeam_aws_default_role.name
  policy_arn = aws_iam_policy.veeam_aws_repository_policy.arn
}



resource "aws_iam_role_policy_attachment" "veeam_aws_vpc_restore_policy_attachment" {
  role       = aws_iam_role.veeam_aws_default_role.name
  policy_arn = aws_iam_policy.veeam_aws_vpc_restore_policy.arn
}

resource "aws_iam_role" "veeam_aws_dlm_role" {
  name = "veeam-aws-dlm-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",      
      "Principal": {
        "Service": "dlm.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "veeam_aws_dlm_role_policy" {
  name = "veeam-aws-dlm-role-policy"
  role = aws_iam_role.veeam_aws_dlm_role.id

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Action": [
            "ec2:CreateSnapshot",
            "ec2:CreateSnapshots",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots"
         ],
         "Resource": "*"
      },
      {
         "Effect": "Allow",
         "Action": [
            "ec2:CreateTags",
            "ec2:DeleteSnapshot"
         ],
         "Resource": "arn:aws:ec2:*::snapshot/*"
      }
   ]
}
EOF
}

### VPC Resources

resource "aws_vpc" "veeam_aws_vpc" {
    cidr_block = "10.60.0.0/16"

  tags = {
    Name = "veeam-aws-vpc"
  }
}

resource "aws_internet_gateway" "veeam_aws_igw" {
  tags = {
    Name = "veeam-aws-igw"
  }
}

resource "aws_internet_gateway_attachment" "veeam_aws_igw_attachment" {
  internet_gateway_id = aws_internet_gateway.veeam_aws_igw.id
  vpc_id              = aws_vpc.veeam_aws_vpc.id
}

resource "aws_route_table" "veeam_aws_route_table" {
  vpc_id = aws_vpc.veeam_aws_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.veeam_aws_igw.id
  }

  tags = {
    Name = "veeam-aws-rt"
  }
}

resource "aws_route_table_association" "veeam_aws_route_table_association" {
  subnet_id      = aws_subnet.veeam_aws_subnet.id
  route_table_id = aws_route_table.veeam_aws_route_table.id
}

resource "aws_subnet" "veeam_aws_subnet" {
  vpc_id                  = aws_vpc.veeam_aws_vpc.id
  cidr_block              = var.subnet_cidr_block_ipv4
  map_public_ip_on_launch = true

  tags = {
    Name = "veeam-aws-subnet"
  }
}

resource "aws_security_group" "veeam_aws_security_group" {
  name        = "veeam-aws-security-group"
  description = "Access to Veeam Backup for AWS appliance"
  vpc_id      = aws_vpc.veeam_aws_vpc.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.veeam_aws_security_group]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_endpoint" "veeam_aws_s3_endpoint" {
  vpc_id            = aws_vpc.veeam_aws_vpc.id
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  route_table_ids   = [aws_route_table.veeam_aws_route_table.id]
}

resource "aws_eip" "veeam_aws_eip" {
  count = var.elastic_ip ? 1 : 0
  vpc   = true
}

resource "aws_eip_association" "veeam_aws_eip_association" {
  count         = var.elastic_ip ? 1 : 0
  instance_id   = aws_instance.veeam_aws_instance.id
  allocation_id = aws_eip.veeam_aws_eip[0].id
}

### EC2 Resources

resource "aws_instance" "veeam_aws_instance" {
  ami                    = local.veeam_aws_instance_ami
  instance_type          = var.veeam_aws_instance_type
  iam_instance_profile   = aws_iam_instance_profile.veeam_aws_instance_profile.name
  subnet_id              = aws_subnet.veeam_aws_subnet.id
  vpc_security_group_ids = [aws_security_group.veeam_aws_security_group.id]

  tags = {
    Name = "veeam-aws-demo"
  }

  user_data = join("\n", [aws_iam_role.veeam_aws_instance_role.arn, aws_iam_role.veeam_aws_default_role.arn])
}

### CloudWatch alarms and Data Lifecycle Manager policy

resource "aws_cloudwatch_metric_alarm" "veeam_aws_recovery_alarm" {
  alarm_name          = "veeam-aws-recovery-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "StatusCheckFailed_System"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Minimum"
  threshold           = "0"
  alarm_description   = "Trigger a recovery when system status check fails for 15 consecutive minutes."
  alarm_actions       = ["arn:aws:automate:${var.aws_region}:ec2:recover"]
  dimensions          = { InstanceId : aws_instance.veeam_aws_instance.id }
}

resource "aws_cloudwatch_metric_alarm" "veeam_aws_reboot_alarm" {
  alarm_name          = "veeam-aws-reboot-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "StatusCheckFailed_Instance"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Minimum"
  threshold           = "0"
  alarm_description   = "Trigger a reboot when instance status check fails for 3 consecutive minutes."
  alarm_actions       = ["arn:aws:automate:${var.aws_region}:ec2:reboot"]
  dimensions          = { InstanceId : aws_instance.veeam_aws_instance.id }
}

resource "aws_dlm_lifecycle_policy" "veeam_aws_dlm_lifecycle_policy" {
  description        = "DLM policy for the Veeam Backup for AWS EC2 instance"
  execution_role_arn = aws_iam_role.veeam_aws_dlm_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]

    schedule {
      name = "Daily snapshots"

      create_rule {
        interval      = 12
        interval_unit = "HOURS"
        times         = ["03:00"]
      }

      retain_rule {
        count = 1
      }

      tags_to_add = {
        type = "VcbDailySnapshot"
      }

      copy_tags = true
    }

    target_tags = {
      Name = "veeam-aws-demo"
    }
  }
}

### S3 bucket to store Veeam backups


resource "aws_s3_bucket" "bkp_instancias_PRD_HMG" {
  bucket = "bkp_instancias_PRD_HMG"

  tags = {
    Name        = "bkp_instancias_PRD_HMG"
    Conta = "BKP"
  }

}



data "aws_iam_policy_document" "Acesso_S3" {
  statement {
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:*"
    ]

    resources = [
      aws_s3_bucket.veeam_aws_bucket.arn,
      "${aws_s3_bucket.veeam_aws_bucket.arn}/*",
    ]

    condition {
      test     = "StringNotLike"
      variable = "aws:userId"

      values = [
        "${var.admin_role_id}:*",
        var.admin_user_id,
        "${aws_iam_role.veeam_aws_default_role.unique_id}:*"
      ]
    }
  }
}

### Outputs

output "veeam_aws_instance_id" {
  description = "The instance ID of the Veeam Backup for AWS EC2 instance"
  value       = aws_instance.veeam_aws_instance.id
}

output "veeam_aws_instance_role_arn" {
  description = "The ARN of the instance role attached to the Veeam Backup for AWS EC2 instance"
  value       = aws_iam_role.veeam_aws_instance_role.arn
}

output "veeam_aws_bucket_name" {
  description = "The name of the provisioned S3 bucket"
  value       = aws_s3_bucket.bkp_instancias_PRD_HMG.id
}