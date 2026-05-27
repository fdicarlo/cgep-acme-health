terraform {
  backend "s3" {
    bucket         = "cgep-acme-health-tfstate-491919374738-us-east-1"
    key            = "main/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cgep-acme-health-tf-locks"
    encrypt        = true
  }
}
