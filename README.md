# har-scraper

A mitm proxy service using the go standard library.

This service generates short lived (30 minute) tls certs that permit the proxying of https traffic and extraction of specific domains/subdomains and response content types.

## Getting started


### 1. config.json setup
```
{
  "Host": "0.0.0.0",            # can be a specific interface or all (127.0.0.1 | 0.0.0.0)
  "ProxyPort": 8080,            # any port
  "filters": {
    "enabled": true,            # disables/enables filter usage (true | false )
    "domain_patterns": [
        "*"                     # can be exact or approximate using "*"
    ],
    "response_content_type": [  
        "application/json"      # define specific response content types or empty "[]"
    ]
  },
  "logging" : {
    "log_matches_only" : true   # simplifies logging to either show only filter matches or show all requests/responses (true | false )
  }
}
```

### 2. start the service
```
go run main.go
```

### 3. install the generated certificate
Manually install certs/ca.crt into your trusted root store

### 4. route your browser or your host machine to the running proxy service

### 5. open your browser and navigate to your desired site

### 6. http events will be saved and organized by domain and subdomain
```
data/
└── example.com/            # domain
    ├── api/                # subdomain
    │   └── 20260101.json   
    └── static/             # subdomain
        └── 20260101.json
```
### 7. enjoy your structured data
