packer {
  required_plugins {
    virtualbox = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/virtualbox"
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
  default = "sentrylens-kali-attacker"
}

variable "memory" {
  type    = number
  default = 4096
}

variable "cpus" {
  type    = number
  default = 2
}

variable "disk_size" {
  type    = number
  default = 40960
}

variable "kali_version" {
  type    = string
  default = "2024.3"
}

variable "ssh_username" {
  type    = string
  default = "kali"
}

variable "ssh_password" {
  type      = string
  sensitive = true
  # Sem default de propósito: tem de vir de -var ou de PKR_VAR_ssh_password
  # (ver packer/.env.example), nunca uma password fixa no repositório.
}

locals {
  timestamp = var.build_timestamp != "" ? var.build_timestamp : formatdate("YYYYMMDD", timestamp())
  output_name = "${var.vm_name}-${local.timestamp}"
}

source "virtualbox-iso" "kali_attacker" {
  vm_name        = local.output_name
  cpus           = var.cpus
  memory         = var.memory
  disk_size      = var.disk_size
  disk_type      = "VDI"
  disk_variant   = "Standard"
  headless       = true
  boot_wait      = "10s"
  boot_command   = [
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "install<enter>",
    "<wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "autoinstall<enter>"
  ]

  iso_urls = [
    "https://cdimage.kali.org/kali-${var.kali_version}/kali-linux-${var.kali_version}-installer-amd64.iso"
  ]
  iso_checksum = "sha256:TODO_UPDATE_WITH_ACTUAL_CHECKSUM"

  http_content = {
    "/user-data" = templatefile("${path.root}/http/user-data.pkrtpl.hcl", {
      ssh_username = var.ssh_username
      ssh_password = var.ssh_password
    })
    "/meta-data" = ""
  }
  http_port_min = 8080
  http_port_max = 8100

  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_wait_timeout = "30m"
  ssh_handshake_attempts = 30

  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -h now"

  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nictype1", "virtio"],
    ["modifyvm", "{{.Name}}", "--nic1", "bridged"],
    ["modifyvm", "{{.Name}}", "--bridgeadapter1", "auto"],
    ["modifyvm", "{{.Name}}", "--ioapic", "on"],
    ["modifyvm", "{{.Name}}", "--nested-hw-virt", "on"],
  ]

  guest_additions_mode = "attach"
  guest_additions_url  = "file:///usr/share/virtualbox/VBoxGuestAdditions.iso"
}

build {
  name    = "kali-attacker-virtualbox"
  sources = ["source.virtualbox-iso.kali_attacker"]

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
    script = "scripts/02-install-tools.sh"
    env_vars = [
      "SSH_USERNAME=${var.ssh_username}",
      "SSH_PASSWORD=${var.ssh_password}",
    ]
  }

  provisioner "shell" {
    script = "scripts/03-configure-attack-tools.sh"
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

  post-processor "vagrant" {
    keep_input_artifact = false
    output              = "${local.output_name}.box"
    compression_level   = 9
  }
}