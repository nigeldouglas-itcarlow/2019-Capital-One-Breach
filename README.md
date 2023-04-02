# 2019 Capital One Data Breach
Repository was created to highlight the advantages of Project Calico and Open Source Falco, and how they could have been used to prevent the Capital One Data Breach

## Deny Traffic to TOR Exit Nodes

The Tigera/Calico team provide the below ```GlobalThreatFeed``` manifest. <br/>
By running the below command you will be able to get the full list of known IP's associated with ```Tor Bulk Exit List```. 

```
kubectl apply -f https://docs.tigera.io/manifests/threatdef/tor-exit-feed.yaml
```

Dissecting the manifest, we can see that it makes a ```pull``` request against a public-facing IP list. <br/>
It then labels the feeds feed with ```feed: tor``` under the ```globalNetworkSet``` object.
```
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: tor-bulk-exit-list
spec:
  pull:
    http:
      url: https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1
  globalNetworkSet:
    labels:
      feed: tor
```

## Organizing IPTable Rules in Logical Order

```
cat << EOF > tiers.yaml
---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: nigel-security
spec:
  order: 400

---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: capital-one-platform
spec:
  order: 500
EOF
```

Whitelisting ```kube-dns``` traffic in the ```nigel-security``` tier:
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2019-Capital-One-Breach/main/configs/kube-dns.yaml
```

Introducing the ```Capital One``` microservice application <br/>
This creates a ```frontend```, a ```backend```, a ```logging```service, and 2 intermediary microservices
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2019-Capital-One-Breach/main/applications/microservices.yaml
```
