# Easy-wazuh - Wazuh Single Node PoC Installer

Setup a Wazuh single-node service easily on a Debian host with Docker.

## Scope

This project installs a **Wazuh single-node Docker stack** for a proof of concept (PoC), lab, or evaluation environment.

Single-node means that all Wazuh central components run on the same Docker host and the same workload:

- Wazuh manager
- Wazuh indexer
- Wazuh dashboard

The installer can deploy this stack with either the official Wazuh Docker service names, or with clearer fixed component names for lab deployments:

```text
wazuh-indexer01
wazuh-manager01
wazuh-dashboard01
```

## Disclaimer

<p><strong><font color="red">Wazuh single-node proof of concept only. It is not intended for production use.</font></strong></p>

Before designing or deploying a production Wazuh environment, you must evaluate the expected log transaction rate, usually expressed as events/logs per second, the required processing load, retention period, indexed data volume, number of agents, alerting use cases, and peak ingestion scenarios.

In production, Wazuh components should be separated so each layer can absorb the required load:

- Wazuh manager nodes for agent connections, event analysis, rules, and active response.
- Wazuh indexer nodes for indexing, search, storage, and retention.
- Wazuh dashboard nodes for user access and visualization.

This single-node setup does not provide high availability, workload separation, or the resilience expected from a production Wazuh deployment. Separating components makes it possible to scale, tune, monitor, back up, and maintain each layer independently.

## Prerequisites

- A Debian 13 machine, or an existing Docker environment correctly sized for a Wazuh single-node PoC.
- A user account with sudo privileges.
- A stable internet connection for Docker image downloads and Wazuh image pulls.
- Network access from the Wazuh server to the endpoints you want to monitor.
- Network access from monitored endpoints to the Wazuh manager ports.

## Machine specifications

For a simple Wazuh Docker single-node PoC installation, use at least:

```text
CPU:      4 vCPU
RAM:      8 GB
Disk:     50 GB free
OS:       Debian 13, 64-bit
Network:  Static IP address recommended
```

For a more comfortable lab or small internal PoC deployment:

```text
CPU:      4 to 8 vCPU
RAM:      16 GB
Disk:     100 GB free
OS:       Debian 13, 64-bit
Network:  Static IP address or stable DNS name
```

For a PoC expected to evolve with more agents, longer retention, or heavier event volume:

```text
CPU:      8 vCPU or more
RAM:      16 to 32 GB
Disk:     200 GB or more, preferably SSD/NVMe
OS:       Debian 13, 64-bit
Network:  Static IP address and DNS record
```

The official Wazuh Docker documentation gives the baseline for a single-node stack as 4 CPU cores, 8 GB RAM, and 50 GB disk. Plan more disk space if you keep logs and security events for a long time. These profiles are PoC-oriented starting points, not production sizing guidance.

## Official documentation

Official Wazuh documentation:

<https://documentation.wazuh.com/current/>

The official Wazuh Docker deployment documentation is available here:

<https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>

## Installation

On the Debian 13 machine, either clone this repository:

```bash
git clone https://github.com/cedricdicesare/Easy-wazuh.git
cd Easy-wazuh
```

It is also possible to copy only the content of `Wazuh-installer.sh` into a new script file on the Debian 13 machine.

```bash
nano Wazuh-installer.sh
```

Make the script executable:

```bash
chmod +x Wazuh-installer.sh
```

Run the installer with sudo:

```bash
sudo ./Wazuh-installer.sh
```

The installer asks for the public FQDN or IP address that clients will use to reach the Wazuh VM. For repeatable test deployments, you can provide it non-interactively:

```bash
sudo WAZUH_PUBLIC_FQDN=wazuh.example.com ./Wazuh-installer.sh
```

This value is used for the dashboard URL and for the generated dashboard certificate configuration. Internal container-to-container traffic uses the service names selected by the topology choice.

At startup, the script asks which installation mode to use:

```text
1) Fresh Debian installation - install Docker and prerequisites
2) Existing Docker environment - keep current Docker installation
```

The script then asks which Wazuh Docker topology to use:

```text
1) Single-node official stack - Wazuh default service names
2) Three named components - manager, indexer, dashboard as separate containers/images
```

Both choices run the Wazuh manager, indexer, and dashboard on the same Docker host for PoC/lab use. The difference is naming:

- `Single-node official stack` keeps the official service names: `wazuh.indexer`, `wazuh.manager`, and `wazuh.dashboard`.
- `Three named components` rewrites the stack to use `wazuh-indexer01`, `wazuh-manager01`, and `wazuh-dashboard01` as service names and fixed container names. The manager, indexer, and dashboard keep their separate Wazuh Docker images.

The script asks for confirmation before continuing with the selected mode and topology. It also asks for a final confirmation before starting the Wazuh containers. The script explicitly reminds the user that this is a single-node PoC deployment, not a production deployment.

In fresh Debian mode, the script installs Docker, configures the Wazuh indexer kernel requirement, clones the official Wazuh Docker repository, generates self-signed certificates, starts the single-node stack, and prints the access information at the end.

In existing Docker mode, the script checks that Docker and the Docker Compose plugin are already available before continuing. It does not remove or reinstall Docker packages.

## FQDN and certificates

The public FQDN or IP address is used for the dashboard access URL and the generated dashboard certificate configuration. The script validates the value and warns if the FQDN does not resolve to the detected VM IP address.

For repeatable VM tests, create or update DNS before deployment, or pass the expected name explicitly:

```bash
sudo WAZUH_PUBLIC_FQDN=wazuh.lab.example ./Wazuh-installer.sh
```

DNS requirements:

```text
wazuh.lab.example  A/AAAA  <WAZUH_VM_IP>
```

This is the only DNS record required by this PoC Docker deployment. Use the customer's real FQDN and VM IP address. The selected FQDN is what users enter in their browser and what agents can use to reach the Wazuh manager ports on the VM.

When the `Three named components` topology is selected, `wazuh-indexer01`, `wazuh-manager01`, and `wazuh-dashboard01` are Docker service/container names inside the Docker network. They do not require public DNS records for this single-VM deployment.

Internal Wazuh component traffic stays inside the Docker network and uses the selected service names. This means the public FQDN is for users and agents reaching the VM, not for dashboard-to-indexer or manager-to-indexer communication.

If certificates already exist under `/opt/wazuh/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs`, the script keeps them only when they match the selected topology and public endpoint metadata. If you change topology or FQDN between runs, move the existing certificate directory away before generating new certificates.

## Docker safety checks

The installer is designed to avoid damaging an existing Docker host.

It does **not** run destructive Docker cleanup commands such as:

```bash
docker system prune
docker volume prune
docker compose down -v
```

If `Fresh Debian installation` mode is selected but Docker is already installed and containers or images exist, the script stops before modifying Docker packages. This prevents an accidental fresh-install path from impacting existing workloads.

If `Existing Docker environment` mode is selected, the script keeps the current Docker installation and only checks that `docker` and `docker compose` are available.

Before starting Wazuh, the script checks whether the default Wazuh ports are already in use:

```text
443    Wazuh dashboard HTTPS
1514   Wazuh agent events TCP
1515   Wazuh agent enrollment TCP
514    Syslog UDP
55000  Wazuh server API HTTPS
9200   Wazuh indexer API HTTPS
```

If one of these ports is already used by another service or container, the script stops instead of replacing or breaking the existing workload.

If containers with `wazuh` in their name already exist, the script warns the user and asks for confirmation before continuing.

By default, the installer uses Wazuh `v4.14.5`, matching the current official Docker documentation when this project was written. To install another Wazuh Docker tag:

```bash
sudo WAZUH_VERSION=v4.14.5 ./Wazuh-installer.sh
```

## Updating Docker images without losing data

**Before any update, make a complete backup or snapshot of the Debian machine.** This is strongly recommended so you can restore the full Wazuh installation if the update fails.

Wazuh data, configuration, certificates, indexed events, and dashboard data are stored in Docker volumes and mounted files under `/opt/wazuh/wazuh-docker/single-node`. A normal container update recreates containers but keeps these persistent resources.

To update within the same checked-out Wazuh Docker version:

```bash
cd /opt/wazuh/wazuh-docker/single-node
sudo docker compose pull
sudo docker compose up -d
```

Then check the container status:

```bash
sudo docker compose ps
```

Do not use the following commands unless you intentionally want to delete Wazuh data:

```bash
sudo docker compose down -v
sudo docker volume prune
sudo docker system prune --volumes
```

The `-v` and `--volumes` options remove Docker volumes. Removing volumes can delete Wazuh configuration, certificates, agents, indexed events, dashboard data, and other persistent content.

## Web interface URL

After installation, the Wazuh dashboard is available at:

```text
https://<public-fqdn-or-ip>
```

If the public FQDN is not available or not resolvable from your browser, use the server IP address instead:

```text
https://<server-ip>
```

The official single-node Docker Compose configuration exposes the dashboard on HTTPS port `443`.

## Ports

The default Wazuh single-node Docker deployment exposes these ports:

```text
443    Wazuh dashboard HTTPS
1514   Wazuh agent events TCP
1515   Wazuh agent enrollment TCP
514    Syslog UDP
55000  Wazuh server API HTTPS
9200   Wazuh indexer API HTTPS
```

No port needs to be added to the dashboard URL with the default Wazuh Docker Compose configuration:

```text
https://<public-fqdn-or-ip>
```

Only specify a port if you changed the Docker Compose port mapping manually.

## Network access restriction

By default, the official Wazuh single-node Docker Compose file publishes its service ports on the Docker host. With Docker port publishing, do not rely only on classic `ufw` rules: Docker manages its own forwarding rules, and traffic to published container ports can bypass the usual `INPUT` chain filtering.

Use the Docker `DOCKER-USER` chain to filter traffic before Docker accepts forwarded packets to published container ports. Replace every placeholder with the customer network plan before deployment:

```text
External interface:  <EXTERNAL_INTERFACE>
Admin subnet:        <ADMIN_SUBNET>
Agent subnet:        <AGENT_SUBNET>
API client subnet:   <API_CLIENT_SUBNET>
Syslog subnet:       <SYSLOG_SUBNET>
```

Find the default outbound interface on the VM before replacing `<EXTERNAL_INTERFACE>`:

```bash
ip route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}'
```

Example baseline rules:

```bash
sudo iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I DOCKER-USER 2 -i <EXTERNAL_INTERFACE> -p tcp --dport 443 -s <ADMIN_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 3 -i <EXTERNAL_INTERFACE> -p tcp --dport 1514 -s <AGENT_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 4 -i <EXTERNAL_INTERFACE> -p tcp --dport 1515 -s <AGENT_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 5 -i <EXTERNAL_INTERFACE> -p udp --dport 514 -s <SYSLOG_SUBNET> -j ACCEPT

sudo iptables -I DOCKER-USER 6 -i <EXTERNAL_INTERFACE> -p tcp --dport 55000 -s <API_CLIENT_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 7 -i <EXTERNAL_INTERFACE> -p tcp --dport 9200 -s <ADMIN_SUBNET> -j ACCEPT

sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 443 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 1514 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 1515 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p udp --dport 514 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 55000 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 9200 -j DROP
```

Port intent:

```text
443/tcp    Dashboard web access. Allow only administrators or trusted user networks.
1514/tcp   Wazuh agent event traffic. Allow only enrolled endpoint networks.
1515/tcp   Wazuh agent enrollment. Allow only endpoint networks during enrollment.
514/udp    Syslog ingestion. Allow only trusted syslog senders.
55000/tcp  Wazuh manager API. Avoid public exposure; allow only approved API clients or automation sources.
9200/tcp   Wazuh indexer API. Avoid public exposure; allow only admin/backup/maintenance sources if needed.
```

If the indexer API is not required from outside the Docker host, do not add the `9200/tcp` allow rule. If the manager API is not required from outside the Docker host, do not add the `55000/tcp` allow rule.

The exact rules depend on the client environment:

- If agents come from several networks, add one allow rule per agent subnet for `1514/tcp` and `1515/tcp`.
- If API clients or automation systems come from several networks, add one allow rule per approved API client subnet for `55000/tcp`.
- If syslog sources use TCP instead of UDP, add an explicit `514/tcp` allow and drop pair.
- If the VM has IPv6 enabled and Docker publishes IPv6 ports, mirror the policy with `ip6tables`.
- Make these rules persistent with the distribution firewall tooling, for example `iptables-persistent` on Debian, after validating them on the test VM.

Do not apply the final `DROP` rules until the customer-approved dashboard, agent, API client, and syslog source networks are known. Applying the drops too early can block legitimate agents, API clients, or log senders.

Before exposing the VM outside an isolated lab, verify the effective policy:

```bash
sudo iptables -S DOCKER-USER
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml ps
```

Then test from allowed and denied source networks. The deployment should be considered incomplete until dashboard, agent, enrollment, syslog, API, and indexer exposure match the customer security requirements.

## Certificates

The Wazuh Docker stack requires certificates to secure communication between Wazuh components. This installer uses the official `wazuh-certs-generator` Docker image to generate Wazuh self-signed certificates for the single-node stack.

Browsers will usually display a security warning when accessing the Wazuh dashboard with these self-signed certificates.

For any environment beyond a PoC, review the official Wazuh certificate documentation and use certificates issued by an internal or public certificate authority trusted by your organization and browsers. Do not treat the generated PoC certificates as production-ready material.

## Default credentials

```text
Username: admin
Password: SecretPassword
```

These are the default Wazuh Docker dashboard credentials documented by Wazuh for the initial login.

Default credentials are suitable only for an initial PoC/lab installation. Change the dashboard password and review all default Wazuh Docker credentials before connecting real endpoints or exposing the service to other users.

The Wazuh Docker stack also contains internal service credentials used by the Wazuh API, indexer, and dashboard integrations. Review the official Wazuh password change procedure instead of changing only the dashboard password manually.

Follow the official Wazuh documentation for password changes:

<https://documentation.wazuh.com/current/deployment-options/docker/index.html#changing-the-default-password-of-wazuh-users>

## Mini Wazuh configuration tutorial

After installation, wait until all containers are running and healthy:

```bash
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml ps
```

The dashboard can take a few minutes to become available while the Wazuh indexer starts. During startup, dashboard logs can show temporary connection errors to the indexer.

To enroll an endpoint:

1. Open the Wazuh dashboard.
2. Log in with the initial admin credentials.
3. Go to `Agents`.
4. Click `Deploy new agent`.
5. Select the endpoint operating system.
6. Enter the Wazuh manager IP address or DNS name.
7. Copy the generated installation command.
8. Run it on the endpoint with administrator or root privileges.
9. Start or restart the Wazuh agent on the endpoint.
10. Confirm that the agent appears as active in the dashboard.

Create groups when endpoints need different monitoring policies. For example, use separate groups for Linux servers, Windows workstations, domain controllers, DMZ systems, or critical assets.

After agents are enrolled, review the dashboard modules for security events, vulnerability detection, file integrity monitoring, configuration assessment, and MITRE ATT&CK mapping.

## Disclaimer

This script is provided as a proposal/example and was developed as part of a proof of concept (PoC). It has not been tested in a production environment. Before any use or deployment in production, users must take all necessary precautions, review and understand the code, adapt it to their own context, and thoroughly test it.

## License

This project is licensed under the GNU General Public License v3.0 (`GPL-3.0-only`).

You can use, copy, share, and modify this project under the terms of the GPL.

Full license text: <https://www.gnu.org/licenses/gpl-3.0.html>
