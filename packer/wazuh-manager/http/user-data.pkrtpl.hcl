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
    primary:
      - arches: [amd64]
        uri: http://archive.ubuntu.com/ubuntu
    security:
      - arches: [amd64]
        uri: http://security.ubuntu.com/ubuntu
  storage:
    layout:
      name: lvm
  identity:
    hostname: sentrylens-wazuh
    username: ${ssh_username}
    # Conta bloqueada (sem password válida) até ao late-command abaixo a definir
    # a partir de SENTRYLENS_WAZUH_SSH_PASSWORD (packer/.env, nunca commitada).
    password: "*"
    realname: "SentryLens User"
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
    - virtualbox-guest-utils
    - virtualbox-guest-dkms
  late-commands:
    - curtin in-target --target=/target -- bash -c "echo '${ssh_username}:${ssh_password}' | chpasswd"
    - echo '${ssh_username} ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/${ssh_username}
    - chmod 440 /target/etc/sudoers.d/${ssh_username}
    - curtin in-target --target=/target -- systemctl enable ssh
    - curtin in-target --target=/target -- systemctl enable vboxadd-service
    - curtin in-target --target=/target -- systemctl enable vboxadd