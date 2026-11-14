# Kafka replay runbook

Manual procedure for the Phase 6 kafka transport (`output.mode: kafka`).
Runs outside CI; needs Docker and ~2 GB RAM. Everything below assumes the
repository root as working directory.

The compose file names the containers `kafka` and `clickhouse`, so the
`docker exec` commands below work as written.

## 1. Start the infrastructure

```bash
docker compose -f docker-compose.kafka.yml up -d
```

Both containers report `Up` within ~10 s. ClickHouse runs with the
passwordless `default` user reachable from the host (`CLICKHOUSE_SKIP_USER_SETUP`),
which is fine for this local-only stack — do not reuse this compose file
anywhere real.

## 2. Create the topic (7-day retention, 4 partitions)

```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-topics.sh --create \
  --topic netflow.raw --partitions 4 --config retention.ms=604800000 \
  --bootstrap-server localhost:9092
```

Verify:

```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-topics.sh --describe \
  --topic netflow.raw --bootstrap-server localhost:9092
```

```text
Topic: netflow.raw	TopicId: FhmjeMa3TF2g1ui3JixW4Q	PartitionCount: 4	ReplicationFactor: 1	Configs: retention.ms=604800000
	Topic: netflow.raw	Partition: 0	Leader: 0	Replicas: 0	Isr: 0
	...
```

## 3. Produce with the sensor

Set `output.mode: kafka` in `config/sensor.yaml`, then:

```bash
cargo run -p sentinel-sensor -- --config config/sensor.yaml
```

Flows are published as one JSON message per `FlowRow`, partition key =
hex xxh3_64 of the 5-tuple. Note: payloads are byte-exact octet arrays
(flow_id/IP are not human-readable strings); inspect row counts in
ClickHouse instead of reading Kafka payloads. A message really does look
like this:

```text
{"flow_id":[12,157,...],"timestamp_start":1790000000123,"source_ip":[0,0,...,255,255,10,0,0,1],...}
```

## 4. Consume with the sink

```bash
cargo run -p sentinel-sink -- --config config/sink.yaml
```

Verify in ClickHouse:

```bash
docker exec clickhouse clickhouse-client --query \
  "SELECT count() FROM sentinel.network_flows"
```

```text
5
```

The sink creates the `sentinel` database and the `network_flows` table on
its first write, so the query errors with `Database sentinel does not exist`
until then.

## 5. Replay demo (sink restart)

1. Stop the sink (Ctrl-C), keep the sensor running for a few more seconds
   (or replay an earlier window — retention is 7 days), then stop it.
2. Restart the sink. The consumer group `clickhouse-sinker` resumes from its
   committed offsets and processes everything produced while it was down.
3. `SELECT count() FROM sentinel.network_flows` has grown by the missed rows.

Verified: 5 rows before the stop, 3 flows produced while the sink was down,
8 rows after the restart. `--describe` showed the 3-row lag draining to 0.

With several partitions, a single sink can take a few seconds to be
reassigned after a restart; query again if the count looks stale.

## 6. Full replay (offset reset — duplicates are expected and accepted)

With the sink stopped:

```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --group clickhouse-sinker \
  --reset-offsets --to-earliest --execute --topic netflow.raw
```

```text
GROUP                          TOPIC                          PARTITION  NEW-OFFSET
clickhouse-sinker              netflow.raw                    0          0
clickhouse-sinker              netflow.raw                    1          0
clickhouse-sinker              netflow.raw                    2          0
clickhouse-sinker              netflow.raw                    3          0
```

Restart the sink: the whole retained topic is re-read, so `network_flows`
gains duplicate rows (at-least-once semantics — established project ruling).

Verified: 8 rows before the reset, 16 after the restart, with
`uniqExact(flow_id)` still 8.

`--reset-offsets` refuses to run while the group still has members. After a
Ctrl-C the group is `Empty` within a few seconds; after a hard kill wait up
to about a minute (`--describe --state` shows `Empty`) before retrying.

## Teardown

```bash
docker compose -f docker-compose.kafka.yml down -v
```
