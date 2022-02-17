# Usage:
# Install and initialize Google Cloud SDK
# Create a file named `terraform.tfvars`
# and set the values of the variables defined in `variables.tf`:
# project = "gcp-social-network-123456"
#
# Windows may hide file extensions by default.
# On Windows, make sure the file extension of the terraform.tfvars is correct,
# e.g. not "terraform.tfvars.txt".
#
# DO NOT create `terraform.tfvars` within child modules (e.g. under ./vm).
# Instead, create `terraform.tfvars` at the root module.
#
# terraform init      Initialize a Terraform working directory
# terraform validate  Validates the Terraform files
# terraform fmt       Rewrites config files to canonical format
# terraform plan      Generate and show an execution plan
# terraform apply     Builds or changes infrastructure
# terraform destroy   Destroy Terraform-managed infrastructure
# terraform state list  List resources
#
# We recommend that you read the provided templates to learn. Meanwhile, it is
# not mandatory and not graded.

provider "google" {
  region = var.region
}

resource "random_id" "name" {
  byte_length = 2
}

resource "google_compute_image" "student-image" {
  name    = var.google_compute_image_name
  project = var.project

  raw_disk {
    source = var.google_compute_image_source
  }

  # Increase the timeouts for the operations on the image
  timeouts {
    create = "15m"
    update = "15m"
    delete = "15m"
  }
}

# GCP firewall rules are applied at the virtual networking level
resource "google_compute_firewall" "default" {
  name    = "cloud-computing-project-image-firewall"
  network = "default"
  project = var.project

  allow {
    protocol = "tcp"

    # "22" SSH
    # "80" HTTP
    # "8000" backend
    ports = ["22", "80", "8000"]
  }
  source_ranges = ["0.0.0.0/0"]
}

# In modules we only specify a name rather than a name and a type as we do for resources.
# This name is used elsewhere in the configuration to reference the module and its outputs.
module "student-vm" {
  # The arguments used in a module block, correspond to variables within the module itself.
  # You can therefore discover all the available variables for a module by inspecting the source of it.
  source = "./vm"

  # the vm name
  name = "student-vm"

  # pass the variables from the root module to the child module
  project      = var.project
  image        = google_compute_image.student-image.self_link
  machine_type = "n1-standard-1"
}

