package cloud.security

default allow = false

# Rule 1: Flag S3 buckets with public-read or public-read-write ACLs
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_s3_bucket"
    resource.attributes.acl == "public-read"
    msg := sprintf("S3 bucket '%v' has a public-read ACL enabled, exposing sensitive data to the internet.", [resource.attributes.bucket])
}

# Rule 2: Flag S3 buckets lacking server-side encryption configuration (handles missing or null)
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_s3_bucket"
    encryption := object.get(resource.attributes, "server_side_encryption_configuration", null)
    encryption == null
    msg := sprintf("S3 bucket '%v' lacks server-side encryption configuration at rest.", [resource.attributes.bucket])
}
