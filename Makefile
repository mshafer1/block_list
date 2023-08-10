all: reports

reports: cloud_ips_simplified.json cloud_ips_bad_actors_simplified.json


cloud_ips_simplified.json: cloud_ips.json | .venv/bin/python
	poetry run python -m ip_calc --pretty --output $@ $^

cloud_ips_bad_actors_simplified.json: cloud_ips.json bad_actors.json | .venv/bin/python
	poetry run python -m ip_calc --pretty --output $@ $^

.venv/bin/python: poetry.lock
	poetry install
