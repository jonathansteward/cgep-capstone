# Remote state in the bucket created by ../bootstrap so CI can plan and apply.
terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-149030068572"
    key          = "acme-health-intake/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
