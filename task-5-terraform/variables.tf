variable "aws_region" { type = string; default = "us-east-1" }
variable "project" { type = string; default = "arzens-secure" }
variable "vpc_cidr" { type = string; default = "10.20.0.0/16" }
variable "public_subnet_cidr" { type = string; default = "10.20.1.0/24" }
variable "admin_cidr_blocks" { type = list(string); description = "Trusted administrator CIDRs; never use 0.0.0.0/0"; sensitive = true }
variable "instance_type" { type = string; default = "t3.micro" }
variable "key_name" { type = string; sensitive = true }
variable "evidence_bucket_name" { type = string; description = "Globally unique private bucket name"; sensitive = true }
