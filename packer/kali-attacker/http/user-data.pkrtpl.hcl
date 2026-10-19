#cloud-config
autoinstall:
  version: 1
  locale: en_US
  keyboard:
    layout: us
    variant: ''
  network:
    network:
      version: 2
      ethernets:
        eth0:
          dhcp4: true
  apt:
    geoip: true
    preserve_sources_list: false
  storage:
    layout:
      name: lvm
  identity:
    hostname: sentrylens-kali
    username: ${ssh_username}
    # Conta bloqueada (sem password válida) até ao late-command abaixo a definir
    # a partir de SENTRYLENS_KALI_SSH_PASSWORD (packer/.env, nunca commitada).
    password: "*"
    realname: "Kali User"
  ssh:
    allow-pw: true
    install-server: true
    authorized-keys: []
  packages:
    - openssh-server
    - curl
    - wget
    - gnupg
    - lsb-release
    - ca-certificates
    - python3
    - python3-pip
    - python3-venv
    - virtualbox-guest-utils
    - virtualbox-guest-dkms
    - linux-headers-$(uname -r)
    - nmap
    - hydra
    - john
    - hashcat
    - sqlmap
    - metasploit-framework
    - crackmapexec
    - impacket-scripts
    - bloodhound
    - neo4j
    - gobuster
    - dirb
    - nikto
    - wpscan
    - enum4linux
    - smbclient
    - rpcclient
    - ldap-utils
    - kerberos-user
    - proxychains4
    - torsocks
    - sshpass
  late-commands:
    - curtin in-target --target=/target -- bash -c "echo '${ssh_username}:${ssh_password}' | chpasswd"
    - echo '${ssh_username} ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/${ssh_username}
    - chmod 440 /target/etc/sudoers.d/${ssh_username}
    - curtin in-target --target=/target -- systemctl enable ssh
    - curtin in-target --target=/target -- systemctl enable vboxadd-service
    - curtin in-target --target=/target -- systemctl enable vboxadd