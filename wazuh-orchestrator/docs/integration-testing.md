# Integration Testing Checklist

Run these checks only on a prepared Docker/Wazuh integration machine, not on the small development host.

- [ ] installation native orchestrator
- [ ] installation container orchestrator
- [ ] detection real Easy-Wazuh topology
- [ ] status against real Docker
- [ ] status against real Wazuh API
- [ ] analyze healthy cluster
- [ ] plan 1 -> 2 workers
- [ ] certificate generation validation
- [ ] docker compose override validation
- [ ] real worker creation
- [ ] new worker Docker health
- [ ] new worker Wazuh cluster join
- [ ] NGINX integration
- [ ] agent redistribution
- [ ] dashboard remains available
- [ ] log collection continues
- [ ] rollback on worker failure
- [ ] rollback on nginx failure
- [ ] scale-down
- [ ] agent reconnection
- [ ] no existing volumes deleted
- [ ] no existing container unnecessarily recreated
- [ ] baseline protection
- [ ] max worker protection

Continuity checks:

- before scaling: record received events, agents and cluster status
- during scaling: verify existing workers remain running
- after scaling: verify no obvious event ingestion gap

Do not claim zero event loss before these integration tests pass.
