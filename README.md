# Easy-wazuh - Wazuh Single Node PoC Installer

Setup a Wazuh single-node service easily on a Debian host with Docker.

## Scope

This project installs a **Wazuh single-node Docker stack** for a proof of concept (PoC), lab, or evaluation environment.

Single-node means that all Wazuh central components run on the same Docker host and the same workload:

- Wazuh manager
- Wazuh indexer
- Wazuh dashboard

## Disclaimer

This installer is provided for a **Wazuh single-node proof of concept only**. It is not intended for production use.

Before designing or deploying a production Wazuh environment, you must evaluate the expected log transaction rate, usually expressed as events/logs per second, the required processing load, retention period, indexed data volume, number of agents, alerting use cases, and peak ingestion scenarios.

In production, Wazuh components should be separated so each layer can absorb the required load:

- Wazuh manager nodes for agent connections, event analysis, rules, and active response.
- Wazuh indexer nodes for indexing, search, storage, and retention.
- Wazuh dashboard nodes for user access and visualization.

This single-node setup does not provide high availability, workload separation, or the resilience expected from a production Wazuh deployment. Separating components makes it possible to scale, tune, monitor, back up, and maintain each layer independently.

## Prerequisites

- A Debian 13 machine.
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

At startup, the script asks which installation mode to use:

```text
1) Fresh Debian installation - install Docker and prerequisites
2) Existing Docker environment - keep current Docker installation
```

The script asks for confirmation before continuing with the selected mode. It also asks for a final confirmation before starting the Wazuh containers. The script explicitly reminds the user that this is a single-node PoC deployment, not a production deployment.

In fresh Debian mode, the script installs Docker, configures the Wazuh indexer kernel requirement, clones the official Wazuh Docker repository, generates self-signed certificates, starts the single-node stack, and prints the access information at the end.

In existing Docker mode, the script checks that Docker and the Docker Compose plugin are already available before continuing. It does not remove or reinstall Docker packages.

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
https://<server-fqdn>
```

If the server FQDN is not available or not resolvable from your browser, use the server IP address instead:

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
https://<server-fqdn>
```

Only specify a port if you changed the Docker Compose port mapping manually.

## Network access restriction

By default, the official Wazuh single-node Docker Compose file publishes its service ports on the Docker host. Restrict access according to your environment before exposing the server to untrusted networks.

For example, with `ufw`, allow dashboard access only from an internal subnet:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 443 proto tcp
```

Agent ports should normally be reachable only by endpoints that must enroll or send events to this Wazuh manager:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 1514 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 1515 proto tcp
```

Avoid exposing ports `9200` and `55000` to untrusted networks.

## HTTPS certificate

The default Wazuh Docker setup uses self-signed certificates. Browsers will usually display a security warning for this certificate.

For production usage, or to avoid browser warnings, install TLS certificates issued by a certificate authority trusted by browsers.

## Default credentials

```text
Username: admin
Password: SecretPassword
```

Change all default Wazuh passwords after the first login and before any production usage. Default credentials are suitable only for an initial lab installation.

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
