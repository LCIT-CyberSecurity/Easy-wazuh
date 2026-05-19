#!/bin/bash

set -Eeuo pipefail
umask 077

echo "=================================================="
echo " Easy-wazuh Ansible agent deployment generator"
echo "=================================================="
echo ""
echo "Scope:"
echo "  This script creates an Ansible inventory and playbook to deploy Wazuh"
echo "  agents on Linux endpoints."
echo "  The Wazuh manager address must be a full FQDN including the domain."
echo "  Example: wazuh.customer.example"
echo ""

WAZUH_MANAGER_FQDN="${WAZUH_MANAGER_FQDN:-}"
ANSIBLE_PROJECT_DIR="${ANSIBLE_PROJECT_DIR:-./ansible-wazuh-agent-deploy}"
ANSIBLE_INVENTORY_FILE="${ANSIBLE_INVENTORY_FILE:-}"
WAZUH_DISABLE_REPO_AFTER_INSTALL="${WAZUH_DISABLE_REPO_AFTER_INSTALL:-yes}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-}"
RUN_ANSIBLE_PLAYBOOK="${RUN_ANSIBLE_PLAYBOOK:-}"

is_valid_fqdn() {
  local VALUE="$1"
  local LABEL
  local -a LABELS

  if [ "${#VALUE}" -gt 253 ]; then
    return 1
  fi

  if [[ ! "$VALUE" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
    return 1
  fi

  if [[ "$VALUE" != *.* ]]; then
    return 1
  fi

  IFS='.' read -r -a LABELS <<< "$VALUE"
  for LABEL in "${LABELS[@]}"; do
    if [ -z "$LABEL" ] || [ "${#LABEL}" -gt 63 ]; then
      return 1
    fi

    if [[ ! "$LABEL" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      return 1
    fi
  done

  return 0
}

confirm_or_default_no() {
  local PROMPT="$1"
  local ANSWER

  read -r -p "$PROMPT [y/N]: " ANSWER

  case "$ANSWER" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

prompt_wazuh_manager_fqdn() {
  local ENTERED_FQDN

  while true; do
    if [ -n "$WAZUH_MANAGER_FQDN" ]; then
      ENTERED_FQDN="$WAZUH_MANAGER_FQDN"
    else
      read -r -p "Wazuh manager FQDN agents will use: " ENTERED_FQDN
    fi

    if is_valid_fqdn "$ENTERED_FQDN"; then
      WAZUH_MANAGER_FQDN="$ENTERED_FQDN"
      return 0
    fi

    echo "Invalid FQDN: $ENTERED_FQDN"
    echo "Use a full DNS name including the domain, for example wazuh.customer.example."

    if [ -n "$WAZUH_MANAGER_FQDN" ]; then
      exit 1
    fi
  done
}

prompt_project_dir() {
  local ENTERED_DIR

  if [ ! -t 0 ]; then
    ANSIBLE_INVENTORY_FILE="${ANSIBLE_INVENTORY_FILE:-$ANSIBLE_PROJECT_DIR/inventory.ini}"
    return 0
  fi

  read -r -p "Ansible project directory [$ANSIBLE_PROJECT_DIR]: " ENTERED_DIR
  if [ -n "$ENTERED_DIR" ]; then
    ANSIBLE_PROJECT_DIR="$ENTERED_DIR"
  fi

  ANSIBLE_INVENTORY_FILE="${ANSIBLE_INVENTORY_FILE:-$ANSIBLE_PROJECT_DIR/inventory.ini}"
}

prompt_optional_agent_group() {
  local ENTERED_GROUP

  if [ -n "$WAZUH_AGENT_GROUP" ]; then
    return 0
  fi

  if [ ! -t 0 ]; then
    return 0
  fi

  read -r -p "Optional Wazuh agent group, leave empty for none: " ENTERED_GROUP
  WAZUH_AGENT_GROUP="$ENTERED_GROUP"
}

write_inventory() {
  if [ -f "$ANSIBLE_INVENTORY_FILE" ]; then
    echo "Keeping existing inventory:"
    echo "  $ANSIBLE_INVENTORY_FILE"
    return 0
  fi

  cat > "$ANSIBLE_INVENTORY_FILE" <<'EOF'
[wazuh_agents]
# Replace these examples with client endpoints reachable by SSH.
# server01 ansible_host=192.0.2.11 ansible_user=debian
# server02 ansible_host=192.0.2.12 ansible_user=ubuntu

[wazuh_agents:vars]
ansible_become=true
EOF

  echo "Created inventory template:"
  echo "  $ANSIBLE_INVENTORY_FILE"
}

write_group_vars() {
  local GROUP_VARS_DIR="$ANSIBLE_PROJECT_DIR/group_vars"

  mkdir -p "$GROUP_VARS_DIR"

  cat > "$GROUP_VARS_DIR/wazuh_agents.yml" <<EOF
---
wazuh_manager_fqdn: "$WAZUH_MANAGER_FQDN"
wazuh_disable_repo_after_install: $([ "$WAZUH_DISABLE_REPO_AFTER_INSTALL" = "yes" ] && echo true || echo false)
wazuh_agent_group: "$WAZUH_AGENT_GROUP"
EOF

  echo "Created variables file:"
  echo "  $GROUP_VARS_DIR/wazuh_agents.yml"
}

write_playbook() {
  cat > "$ANSIBLE_PROJECT_DIR/deploy-wazuh-agent.yml" <<'EOF'
---
- name: Deploy Wazuh agent on Linux endpoints
  hosts: wazuh_agents
  become: true
  gather_facts: true

  vars:
    wazuh_manager_fqdn: ""
    wazuh_disable_repo_after_install: true
    wazuh_agent_group: ""

  pre_tasks:
    - name: Validate manager FQDN
      ansible.builtin.assert:
        that:
          - wazuh_manager_fqdn is match('^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$')
          - "'.' in wazuh_manager_fqdn"
        fail_msg: "wazuh_manager_fqdn must be a full FQDN including the domain."

    - name: Gather installed package facts
      ansible.builtin.package_facts:
        manager: auto

  tasks:
    - name: Install Debian prerequisites
      ansible.builtin.apt:
        name:
          - ca-certificates
          - curl
          - gnupg
          - apt-transport-https
        state: present
        update_cache: true
      when: ansible_os_family == "Debian"

    - name: Install Wazuh APT key
      ansible.builtin.shell: |
        set -e
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
          gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
        chmod 0644 /usr/share/keyrings/wazuh.gpg
      args:
        creates: /usr/share/keyrings/wazuh.gpg
      when: ansible_os_family == "Debian"

    - name: Configure Wazuh APT repository
      ansible.builtin.copy:
        dest: /etc/apt/sources.list.d/wazuh.list
        owner: root
        group: root
        mode: "0644"
        content: |
          deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
      when: ansible_os_family == "Debian"

    - name: Refresh APT cache
      ansible.builtin.apt:
        update_cache: true
      when: ansible_os_family == "Debian"

    - name: Install Wazuh RPM key
      ansible.builtin.rpm_key:
        key: https://packages.wazuh.com/key/GPG-KEY-WAZUH
        state: present
      when: ansible_os_family == "RedHat"

    - name: Configure Wazuh YUM/DNF repository
      ansible.builtin.yum_repository:
        name: wazuh
        description: Wazuh repository
        baseurl: https://packages.wazuh.com/4.x/yum/
        gpgcheck: true
        gpgkey: https://packages.wazuh.com/key/GPG-KEY-WAZUH
        enabled: true
        protect: true
      when: ansible_os_family == "RedHat"

    - name: Install Wazuh agent on Debian family
      ansible.builtin.command: apt-get install -y wazuh-agent
      environment:
        WAZUH_MANAGER: "{{ wazuh_manager_fqdn }}"
        WAZUH_AGENT_GROUP: "{{ wazuh_agent_group }}"
      when:
        - ansible_os_family == "Debian"
        - "'wazuh-agent' not in ansible_facts.packages"

    - name: Install Wazuh agent on RedHat family
      ansible.builtin.command: "{{ ansible_pkg_mgr }} install -y wazuh-agent"
      environment:
        WAZUH_MANAGER: "{{ wazuh_manager_fqdn }}"
        WAZUH_AGENT_GROUP: "{{ wazuh_agent_group }}"
      when:
        - ansible_os_family == "RedHat"
        - "'wazuh-agent' not in ansible_facts.packages"

    - name: Hold Wazuh agent package on Debian family
      ansible.builtin.command: apt-mark hold wazuh-agent
      changed_when: false
      when:
        - ansible_os_family == "Debian"
        - wazuh_disable_repo_after_install | bool

    - name: Disable Wazuh repository on RedHat family
      ansible.builtin.replace:
        path: /etc/yum.repos.d/wazuh.repo
        regexp: '^enabled=1'
        replace: 'enabled=0'
      when:
        - ansible_os_family == "RedHat"
        - wazuh_disable_repo_after_install | bool

    - name: Enable and start Wazuh agent service
      ansible.builtin.systemd:
        name: wazuh-agent
        daemon_reload: true
        enabled: true
        state: started

    - name: Show Wazuh agent status
      ansible.builtin.command: /var/ossec/bin/wazuh-control status
      register: wazuh_agent_status
      changed_when: false

    - name: Print Wazuh agent status
      ansible.builtin.debug:
        var: wazuh_agent_status.stdout_lines
EOF

  echo "Created playbook:"
  echo "  $ANSIBLE_PROJECT_DIR/deploy-wazuh-agent.yml"
}

print_next_steps() {
  echo ""
  echo "=================================================="
  echo " Ansible Wazuh agent deployment files are ready"
  echo "=================================================="
  echo "Manager FQDN:"
  echo "  $WAZUH_MANAGER_FQDN"
  echo ""
  echo "Inventory:"
  echo "  $ANSIBLE_INVENTORY_FILE"
  echo ""
  echo "Edit the inventory and add endpoints under [wazuh_agents], then run:"
  echo ""
  echo "  ansible-playbook -i $ANSIBLE_INVENTORY_FILE $ANSIBLE_PROJECT_DIR/deploy-wazuh-agent.yml"
  echo ""
  echo "Security reminders:"
  echo "  - Agents must resolve $WAZUH_MANAGER_FQDN to the Wazuh server."
  echo "  - Agents must reach TCP 1514 and TCP 1515 on the Wazuh server."
  echo "  - Use a trusted SSH inventory and avoid storing secrets in plain text."
}

run_playbook_if_requested() {
  if [ -z "$RUN_ANSIBLE_PLAYBOOK" ]; then
    if [ ! -t 0 ]; then
      RUN_ANSIBLE_PLAYBOOK="no"
    elif confirm_or_default_no "Run ansible-playbook now"; then
      RUN_ANSIBLE_PLAYBOOK="yes"
    else
      RUN_ANSIBLE_PLAYBOOK="no"
    fi
  fi

  case "$RUN_ANSIBLE_PLAYBOOK" in
    yes)
      if ! command -v ansible-playbook >/dev/null 2>&1; then
        echo "Error: ansible-playbook was not found."
        echo "Install Ansible first, then run the command shown above."
        exit 1
      fi

      ansible-playbook -i "$ANSIBLE_INVENTORY_FILE" "$ANSIBLE_PROJECT_DIR/deploy-wazuh-agent.yml"
      ;;
    no)
      ;;
    *)
      echo "Error: invalid RUN_ANSIBLE_PLAYBOOK value: $RUN_ANSIBLE_PLAYBOOK"
      echo "Expected value: yes or no"
      exit 1
      ;;
  esac
}

prompt_wazuh_manager_fqdn
prompt_project_dir
prompt_optional_agent_group

mkdir -p "$ANSIBLE_PROJECT_DIR"
write_inventory
write_group_vars
write_playbook
print_next_steps
run_playbook_if_requested
