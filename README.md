# Block-List

This repo provides data lists that servers may want to block temporarily.

# :warning: Updater CI paused :warning:

It's failing due to using old utilities. See #2

## Data Source

All data copied here is derived from Internet Storm Center / DShield API
And is shared under the [Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) License](https://creativecommons.org/licenses/by-nc-sa/4.0/) (See also, [LICENSE](LICENSE.md) for a local copy.)


## bad_actors.json

List of IPs that are in the daily report from [Internet Storm Center](https://www.dshield.org/index.html) that have been identified as port scanners for one or more of the following ports:
* 22 (standard SSH port)
* 80 (standard HTTP port)
* 443 (standard HTTPS port)

## cloud_ips.json

List of cloud IPs (in standard "CIDR" notation) from [Internet Storm Center](https://www.dshield.org/index.html)

## cloud_ips__simplified.json

`cloud_ips.json` run through [`ip_calc`](ip_calc) module to remove duplicates.

## cloud_ips__and__bad_actors__simplified.json

`cloud_ips.json` + `bad_actors.json` run through [`ip_calc`](ip_calc) module to remove duplicates.
