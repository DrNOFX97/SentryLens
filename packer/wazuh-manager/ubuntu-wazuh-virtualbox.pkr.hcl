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

variable "lab_network_cidr" {
  type    = string
  default = ""
  # CIDR da rede do laboratório (ex.: a sub-rede do host na bridge) a partir
  # da qual as APIs do Manager (55000) e do Indexer (9200) ficam acessíveis.
  # Vazio = portas fechadas (fail-closed); ver 03-configure-network.sh.
}

variable "vboxmanage_path" {
  type    = string
  default = "VBoxManage"
}

locals {
  timestamp = var.build_timestamp != "" ? var.build_timestamp : formatdate("YYYYMMDD", timestamp())
  output_name = "${var.vm_name}-${local.timestamp}"
}

source "virtualbox-iso" "wazuh_manager" {
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
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "<enter><wait>",
    "autoinstall<enter>"
  ]

  iso_urls = [
    "https://releases.ubuntu.com/jammy/ubuntu-${var.ubuntu_version}-live-server-amd64.iso"
  ]
  # Verificado contra releases.ubuntu.com/jammy/SHA256SUMS em 2026-10-19.
  iso_checksum = "sha256:9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"

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
    ["modifyvm", "{{.Name}}", "--graphicscontroller", "vmsvga"],
    ["modifyvm", "{{.Name}}", "--vrde", "on"],
    ["modifyvm", "{{.Name}}", "--vrdeport", "3389"],
  ]

  guest_additions_mode = "attach"
  guest_additions_url  = "file:///usr/share/virtualbox/VBoxGuestAdditions.iso"
}

build {
  name    = "wazuh-manager-virtualbox"
  sources = ["source.virtualbox-iso.wazuh_manager"]

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
      "LAB_NETWORK_CIDR=${var.lab_network_cidr}",
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

  post-processor "shell-local" {
    inline = [
      "echo 'Build completed: ${local.output_name}'",
      "echo 'OVA file: output-${local.output_name}/${local.output_name}.ova'",
    ]
  }
}