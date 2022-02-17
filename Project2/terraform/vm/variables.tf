# Variables of a child module
# Do not create `terraform.tfvars` within child modules.
# Instead, create `terraform.tfvars` at the root module.
variable name {}

variable project {}

variable zone {
  default = "us-east1-b"
}

variable image {}

variable machine_type {}
