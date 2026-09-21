output "vpc_id" { value = aws_vpc.main.id }
output "security_group_id" { value = aws_security_group.web.id }
output "instance_id" { value = aws_instance.web.id }
output "evidence_bucket" { value = aws_s3_bucket.evidence.bucket }
output "private_endpoint_note" { value = "The instance has no public IP; reach it through a controlled management path." }
