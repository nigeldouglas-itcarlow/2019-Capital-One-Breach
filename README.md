# 2019 Capital One Data Breach
Repository was created to highlight the advantages of Project Calico and Open Source Falco, and how they could have been used to prevent the Capital One Data Breach 

## Create a lightweight, 1 node EKS Cluster:
```
eksctl create cluster capital-one --node-type t3.xlarge --nodes=1 --nodes-min=0 --nodes-max=3 --max-pods-per-node 58
```

![Screenshot 2023-04-03 at 10 38 55](https://user-images.githubusercontent.com/126002808/229472253-d5baf227-803a-408a-8df7-ab5e0505b18b.png)

## Signed-up for Calico Cloud free trial

<img width="1369" alt="Screenshot 2023-04-03 at 10 08 55" src="https://user-images.githubusercontent.com/126002808/229472385-2e139249-da22-4f5e-a809-ddd82d29f4ef.png">


<img width="1080" alt="Screenshot 2023-04-03 at 21 46 52" src="https://user-images.githubusercontent.com/126002808/229625448-6f06e850-31a6-4fc7-ba0d-d81d06027dbd.png">


<img width="1080" alt="Screenshot 2023-04-03 at 21 47 27" src="https://user-images.githubusercontent.com/126002808/229625473-d3485e98-2aaf-4332-986f-87145609e1d0.png">


<img width="1169" alt="Screenshot 2023-04-03 at 21 52 41" src="https://user-images.githubusercontent.com/126002808/229625496-90341cf5-e0ad-430e-bb25-31a1f882e1e5.png">

<img width="1169" alt="Screenshot 2023-04-03 at 21 54 15" src="https://user-images.githubusercontent.com/126002808/229625512-d83eabc9-d439-4eac-89d8-6d91ba3f1068.png">





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

<img width="1169" alt="Screenshot 2023-04-03 at 22 00 41" src="https://user-images.githubusercontent.com/126002808/229626876-37d4949b-9c5d-4048-8d58-a064d7d5d353.png">

<img width="1435" alt="Screenshot 2023-04-03 at 22 02 09" src="https://user-images.githubusercontent.com/126002808/229626979-9821ca6a-0059-4e4c-81d9-a83c1257ed87.png">


Whitelisting ```kube-dns``` traffic in the ```nigel-security``` tier:
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2019-Capital-One-Breach/main/configs/kube-dns.yaml
```

Introducing the ```Capital One``` microservice application <br/>
This creates a ```frontend```, a ```backend```, a ```logging```service, and 2 intermediary microservices
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2019-Capital-One-Breach/main/applications/microservices.yaml
```

## Implement a Zone-Based Architecture (ZBA) to our zero-trust environment

## Introduce the adversary (this is a deployment manifest doing malicious actions)

```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml -n capital-one
```

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
