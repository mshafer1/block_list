all: reports

-include .env
export

ifndef USER_AGENT
$(error USER_AGENT is not set)
endif

clean:
	rm -rf .venv
	rm -f cloud_ips.json
	rm -f bad_actors.json
	rm -f cloudcidrs
	rm -f intelfeed

cloudcidrs:
	sleep 10
	curl -A "$(USER_AGENT)" https://isc.sans.edu/api/cloudcidrs?json | jq "."  > $@
	cat $@ | head -n 10

intelfeed:
	sleep 10
	curl -A "$(USER_AGENT)" https://isc.sans.edu/api/intelfeed?json | jq "." > $@
	cat $@ | head -n 10

bad_actors.json: intelfeed bad_actors.jq
	cat intelfeed | jq -f bad_actors.jq | jq -r tostring > $@

cloud_ips.json: cloudcidrs
	$(shell cat cloudcidrs | jq '[ .[] | .prefix ]'  | tee $@ )

reports: cloud_ips__simplified.json cloud_ips__and__bad_actors__simplified.json bad_actors__simplified.json

bad_actors__simplified.json: bad_actors.json | .venv/bin/python
	poetry run python -m ip_calc --pretty --output $@ $^

cloud_ips__simplified.json: cloud_ips.json | .venv/bin/python
	poetry run python -m ip_calc --pretty --output $@ $^

cloud_ips__and__bad_actors__simplified.json: cloud_ips.json bad_actors.json | .venv/bin/python
	poetry run python -m ip_calc --pretty --output $@ $^

.venv/bin/python: poetry.lock
	poetry install
