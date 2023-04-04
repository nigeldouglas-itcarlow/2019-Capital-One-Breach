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


<img width="1080" alt="Screenshot 2023-04-03 at 21 47 27" src="https://user-images.githubusercontent.com/126002808/229628563-3869c46d-1b8f-48ca-b185-5ecc7addc096.png">



## Proof of Completed Deployment

All the relevant pods are running in my ```EKS``` cluster
<img width="1169" alt="Screenshot 2023-04-03 at 21 54 15" src="https://user-images.githubusercontent.com/126002808/229625512-d83eabc9-d439-4eac-89d8-6d91ba3f1068.png">

We can also see the cluster was connecting in the Calico Cloud UI:

<img width="1435" alt="Screenshot 2023-04-03 at 22 01 27" src="https://user-images.githubusercontent.com/126002808/229628115-5f3b1c7c-716f-47d3-9eaa-200ff9dadf58.png">






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

Opened the file in Vim to explain how the Calico Policy is created within the ```nigel-security``` tier <br/>
The policy is created in the earliest possible tier to make sure traffic is not incorrectly dropped by security rules.

<img width="464" alt="Screenshot 2023-04-03 at 22 15 35" src="https://user-images.githubusercontent.com/126002808/229629443-585b9511-e29f-4b46-a29d-b966f0866b32.png">

Set the correct ```apiVersion``` for the policy <br/>
As you can see, it was a ```globalNetworkPolicy``` - enforced across all network namespaces:

<img width="763" alt="Screenshot 2023-04-03 at 22 19 09" src="https://user-images.githubusercontent.com/126002808/229629927-ad7de977-8db7-4069-9315-57d881ba87c9.png">

Policies appear in the Calico Cloud UI in realtime.

<img width="1438" alt="Screenshot 2023-04-03 at 22 21 08" src="https://user-images.githubusercontent.com/126002808/229630352-0f14e911-c48d-4074-9896-9c6715d7deef.png">


Introducing the ```Capital One``` microservice application <br/>
This creates a ```frontend```, a ```backend```, a ```logging```service, and 2 intermediary microservices
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2019-Capital-One-Breach/main/applications/microservices.yaml
```

<img width="1438" alt="Screenshot 2023-04-03 at 22 23 24" src="https://user-images.githubusercontent.com/126002808/229630704-cae778f3-7ddf-42ca-a087-a53720d7af56.png">

```
kubectl get pods -n capital-one --show-labels
```

![Screenshot 2023-04-04 at 14 59 16](https://user-images.githubusercontent.com/126002808/229817295-b2414351-aee0-41fa-ad48-e56e35db7874.png)

It's also worth pointing-out that all pods are assigned a unique IP address. <br/>
However, due to the ephemeral nature of containerized workloads, pod IP's cannot be relied upon.

```
kubectl get pods -n capital-one -o wide
```

![Screenshot 2023-04-04 at 15 01 08](https://user-images.githubusercontent.com/126002808/229817331-d6b117e3-c94c-43e8-b49b-1b0f576b20cc.png)

For example, if I kill a pod manually, or due to cluster scale-up/down, a pod is self-healing and will recreated. <br/>
Unfortunately, when it recreates it will be assigned a new IP address. Therefore, we should not build rules based on IP addresses.

```
kubectl delete pod backend-786744f846-wn86l -n capital-one
```

![Screenshot 2023-04-04 at 15 15 36](https://user-images.githubusercontent.com/126002808/229822191-263111fc-d643-4b78-a88b-7b89770a0d07.png)


## Implement a Zone-Based Architecture (ZBA) to our zero-trust environment

## Introduce the adversary (this is a deployment manifest doing malicious actions)

I created an attacker-app into the same network namespace as all other workloads. <br/>
By default, Kubernetes defines a flat network - which means all workloads can freely communicate amonst each other:
```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml -n capital-one
```
It's also worth noting that the attacker was intimate with Capital One's network architecture. <br/>
As such, we need use ```admission controllers``` (like Open Policy Agent) to prevent the attacker labelling their workloads at runtime:
![Screenshot 2023-04-04 at 15 03 29](https://user-images.githubusercontent.com/126002808/229817958-825d9f3a-ca9b-4456-bb1a-0235344ccd25.png)

Without Calico policies, all workloads - whether legitimate or not - can freely communicate.
Since Calico scrapes metrics via ```Prometheus``` and streams events via ```FluentD```, we get a real-time view of the activity.

<img width="1080" alt="Screenshot 2023-04-04 at 15 11 34" src="https://user-images.githubusercontent.com/126002808/229820131-40fb1f51-33e7-4a4d-a989-f7592b29caf5.png">

```Green lines``` represent traffic that is ```allowed```.
```Red lines``` represent traffic that is ```denied by policy```.


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


## Scale down your EKS Cluster
Confirm the cluster name
```
eksctl get cluster
```
Find the Node Group ID associated with the cluster
```
eksctl get nodegroup --cluster capital-one
```
Scale the Node Group down to 0 nodes to reduce AWS costs
```
eksctl scale nodegroup --cluster capital-one --name ng-539a90a2 --nodes 0
```

<img width="1438" alt="Screenshot 2023-04-03 at 22 29 41" src="https://user-images.githubusercontent.com/126002808/229631846-ee400bd7-9673-42ee-aebf-1e1d62153f5b.png">

Scale the Node Group back to 1 node to continue testing <br/>
At this point I decided to remotely connect to AWS via EKSCTL CLI tool on my Macbook:
```
eksctl scale nodegroup --cluster capital-one --name ng-539a90a2 --nodes 1
```

![Screenshot 2023-04-04 at 14 05 24](https://user-images.githubusercontent.com/126002808/229801072-f6f38ec9-afbe-49f2-991a-c85f1a7196de.png)



Alternatively, delete the cluster altogether when the tests are performed
```
eksctl delete cluster --name capital-one
```
