# Integration Testing Checklist

Run these checks only on a prepared Docker/Wazuh integration machine.

- [ ] `easy-wazuh-bootstrap.sh` performs existing multi-node bootstrap
- [ ] deployment metadata created
- [ ] deployment metadata accurate
- [ ] default naming
- [ ] custom naming
- [ ] internal FQDN naming
- [ ] padding preserved
- [ ] baseline persisted
- [ ] existing Easy-Wazuh Compose project detected
- [ ] existing networks preserved
- [ ] existing volumes preserved
- [ ] existing containers preserved
- [ ] status on healthy environment
- [ ] analyze on healthy environment
- [ ] next worker name resolves to worker03
- [ ] unique hostname
- [ ] unique Wazuh node_name
- [ ] dedicated worker configuration generated
- [ ] Wazuh CA fingerprint recorded
- [ ] existing cert fingerprints recorded
- [ ] worker03 certificate generated/prepared
- [ ] CA fingerprint unchanged
- [ ] existing cert fingerprints unchanged
- [ ] worker03 certificate valid
- [ ] Dashboard certificate unchanged
- [ ] effective Compose valid
- [ ] worker03 only new service
- [ ] existing services not recreated
- [ ] worker03 Docker healthy
- [ ] worker03 joins Wazuh cluster
- [ ] exactly one master remains
- [ ] NGINX agent traffic upstream updated
- [ ] existing master entry preserved
- [ ] existing workers preserved
- [ ] enrollment backend unchanged unless required by actual topology
- [ ] agents continue collecting during scale
- [ ] no obvious ingestion interruption
- [ ] new worker begins receiving agents
- [ ] distribution stabilizes over time
- [ ] Dashboard remains one instance
- [ ] Dashboard remains reachable
- [ ] Dashboard TLS unchanged
- [ ] indexers unchanged
- [ ] rollback after certificate failure
- [ ] rollback after config failure
- [ ] rollback after Compose failure
- [ ] rollback after Docker health failure
- [ ] rollback after cluster join failure
- [ ] rollback after NGINX failure
- [ ] simulated interrupted transaction detected
- [ ] no worker04 created while worker03 transaction incomplete
- [ ] scale-down worker03
- [ ] worker03 removed from NGINX
- [ ] worker03 stopped gracefully
- [ ] worker03 removed from desired Compose
- [ ] worker03 volume preserved
- [ ] worker03 cannot resurrect after future Compose operation
- [ ] baseline scale-down protection
- [ ] HOST_PRESSURE blocks worker scale-up
- [ ] INDEXER_PRESSURE does not trigger worker scaling
- [ ] DASHBOARD_PRESSURE does not create second Dashboard

Continuity checks:

- before scaling: record received events, agents and cluster status
- during scaling: verify existing workers remain running
- after scaling: verify no obvious event ingestion gap

Do not claim zero event loss before these integration tests pass.
