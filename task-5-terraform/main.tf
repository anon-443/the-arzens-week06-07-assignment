terraform {
  required_version = ">= 1.5.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
  # Production example: configure an encrypted, locked remote backend in the workspace.
  # backend "s3" { bucket = "REPLACE_WITH_TF_STATE_BUCKET" key = "arzens/terraform.tfstate" region = "us-east-1" dynamodb_table = "REPLACE_WITH_LOCK_TABLE" encrypt = true }
}
provider "aws" { region = var.aws_region }

data "aws_availability_zones" "available" { state = "available" }
data "aws_ami" "ubuntu" { most_recent = true; owners = ["099720109477"] filter { name = "name" values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"] } filter { name = "virtualization-type" values = ["hvm"] } }

resource "aws_vpc" "main" { cidr_block = var.vpc_cidr; enable_dns_hostnames = true; enable_dns_support = true; tags = { Name = "${var.project}-vpc" } }
resource "aws_subnet" "public" { vpc_id = aws_vpc.main.id; cidr_block = var.public_subnet_cidr; availability_zone = data.aws_availability_zones.available.names[0]; map_public_ip_on_launch = false; tags = { Name = "${var.project}-public" } }
resource "aws_security_group" "web" { name = "${var.project}-web"; description = "Restricted web access"; vpc_id = aws_vpc.main.id
  ingress { description = "SSH from approved CIDR"; from_port = 22; to_port = 22; protocol = "tcp"; cidr_blocks = var.admin_cidr_blocks }
  ingress { description = "HTTP"; from_port = 80; to_port = 80; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
  ingress { description = "HTTPS"; from_port = 443; to_port = 443; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  tags = { Name = "${var.project}-sg" }
}
resource "aws_instance" "web" { ami = data.aws_ami.ubuntu.id; instance_type = var.instance_type; subnet_id = aws_subnet.public.id; vpc_security_group_ids = [aws_security_group.web.id]; key_name = var.key_name; associate_public_ip_address = false; user_data = file("${path.module}/user_data.sh"); metadata_options { http_tokens = "required"; http_endpoint = "enabled" }; root_block_device { encrypted = true; volume_type = "gp3"; volume_size = 20 }; tags = { Name = "${var.project}-web" } }
resource "aws_s3_bucket" "evidence" { bucket = var.evidence_bucket_name; force_destroy = false; tags = { Name = "${var.project}-evidence" } }
resource "aws_s3_bucket_public_access_block" "evidence" { bucket = aws_s3_bucket.evidence.id; block_public_acls = true; block_public_policy = true; ignore_public_acls = true; restrict_public_buckets = true }
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" { bucket = aws_s3_bucket.evidence.id; rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
resource "aws_s3_bucket_versioning" "evidence" { bucket = aws_s3_bucket.evidence.id; versioning_configuration { status = "Enabled" } }
