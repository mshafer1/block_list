all: reports

reports: cloud_ips_simplified.json 
# cloud_ips_bad_actors_simplified.json


cloud_ips_simplified.json: cloud_ips.json | simplify_and_merge_ip_lists.py .venv/bin/python
	.venv/bin/python simplify_and_merge_ip_lists.py --output $@ --pretty $^

.venv/bin/python: requirements.txt
	python -m venv .venv
	.venv/bin/pip install -r $<
