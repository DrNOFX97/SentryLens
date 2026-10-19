packer {
  required_plugins {
    hyperv = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/hyperv"
    }
  }
}

variable "version" {
  type    = string
  default = "1.0.0"
}

variable "build_timestamp" {
  type    = string
  default = ""
}

variable "vm_name" {
  type    = string
  default = "sentrylens-wazuh-manager"
}

variable "memory" {
  type    = number
  default = 8192
}

variable "cpus" {
  type    = number
  default = 4
}

variable "disk_size" {
  type    = number
  default = 61440
}

variable "ubuntu_version" {
  type    = string
  default = "22.04.5"
}

variable "wazuh_version" {
  type    = string
  default = "4.14.0"
}

variable "ssh_username" {
  type    = string
  default = "sentrylens"
}

variable "ssh_password" {
  type      = string
  sensitive = true
  # Sem default de propósito: tem de vir de -var ou de PKR_VAR_ssh_password
  # (ver packer/.env.example), nunca uma password fixa no repositório.
}

variable "switch_name" {
  type    = string
  default = "Lab-Wazuh"
}

locals {
  timestamp = var.build_timestamp != "" ? var.build_timestamp : formatdate("YYYYMMDD", timestamp())
  output_name = "${var.vm_name}-${local.timestamp}"
}

source "hyperv-iso" "wazuh_manager" {
  vm_name               = local.output_name
  cpus                  = var.cpus
  memory                = var.memory
  disk_size             = var.disk_size
  generation            = 2
  secure_boot           = false
  enable_dynamic_memory = false
  switch_name           = var.switch_name
  iso_urls              = ["https://releases.ubuntu.com/jammy/ubuntu-${var.ubuntu_version}-live-server-amd64.iso"]
  iso_checksum          = "sha256:ae5a8e5c5ae0c7b5f5e0c5e0c5e0c5e0c5e0c5e0c5e0c5e0c5e0c5e0c5e0c5e0c"
  http_content = {
    "/user-data" = templatefile("${path.root}/http/user-data.pkrtpl.hcl", {
      ssh_username = var.ssh_username
      ssh_password = var.ssh_password
    })
    "/meta-data" = ""
  }
  http_port_min = 8080
  http_port_max = 8100
  boot_wait             = "10s"
  boot_command          = [
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "autoinstall<enter>"
  ]
  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_wait_timeout = "30m"
  ssh_handshake_attempts = 30
  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -h now"
  communicator     = "ssh"
}

build {
  name    = "wazuh-manager-hyperv"
  sources = ["source.hyperv-iso.wazuh_manager"]

  provisioner "file" {
    source      = "scripts/"
    destination = "/home/${var.ssh_username}/"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /home/${var.ssh_username}/scripts/*.sh",
    ]
  }

  provisioner "shell" {
    script = "scripts/01-base-setup.sh"
    env_vars = [
      "SSH_USERNAME=${var.ssh_username}",
      "SSH_PASSWORD=${var.ssh_password}",
    ]
  }

  provisioner "shell" {
    script = "scripts/02-install-wazuh.sh"
    env_vars = [
      "WAZUH_VERSION=${var.wazuh_version}",
      "SSH_USERNAME=${var.ssh_username}",
      "SSH_PASSWORD=${var.ssh_password}",
    ]
  }

  provisioner "shell" {
    script = "scripts/03-configure-network.sh"
    env_vars = [
      "SSH_USERNAME=${var.ssh_username}",
      "SSH_PASSWORD=${var.ssh_password}",
    ]
  }

  provisioner "shell" {
    script = "scripts/04-finalize.sh"
    env_vars = [
      "SSH_USERNAME=${var.ssh_username}",
      "SSH_PASSWORD=${var.ssh_password}",
    ]
  }

  post-processor "shell-local" {
    inline = [
      "echo 'Build completed: ${local.output_name}'",
      "echo 'VHDX file: output-${local.output_name}/${local.output_name}.vhdx'",
    ]
  }
}