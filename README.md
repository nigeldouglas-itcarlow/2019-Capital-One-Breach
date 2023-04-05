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


## Introduce the adversary 
This is a deployment manifest doing malicious actions <br/>
<br/>
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

```Green lines``` represent traffic that is ```allowed```. <br/>
```Red lines``` represent traffic that is ```denied by policy```.

## Creating a Zone-Based Architecture

A typical zone-based architecture includes: 

- A DMZ Zone
- Trusted Zone
- Restricted Zone

### Demilitarized Zone (DMZ)
Allow ingress traffic from public IP CIDR nets (18.0.0.0/16) <br/>
All other ingress traffic from workloads is denied. <br/>
<br/>


```
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: capital-one-platform.dmz
  namespace: capital-one
spec:
  tier: capital-one-platform
  order: 0
  selector: fw-zone == "dmz"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      source:
        nets:
          - 18.0.0.0/16
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Allow
      source: {}
      destination:
        selector: fw-zone == "trusted"||app == "logging"
    - action: Deny
      source: {}
      destination: {}
  types:
    - Ingress
    - Egress
```

We can see that the ```dmz``` policy was correctly assigned to the ```capital-one-platform``` tier <br/>
It's also visible that the policy matched ```1 endpoint```

<img width="1437" alt="Screenshot 2023-04-05 at 10 53 54" src="https://user-images.githubusercontent.com/126002808/230047239-a6003b1f-5f64-4a54-8aae-61558042a669.png">

You can also see that policy matched based on the label ```fw-zone: dmz```
We can see all relevant metadata associated with the matched workload.
<img width="1437" alt="Screenshot 2023-04-05 at 10 54 10" src="https://user-images.githubusercontent.com/126002808/230047461-6c4c7ee3-f621-4a36-a526-fd37c60960bc.png">


### Trusted Zone 
Talks between frontend and backend workloads

```
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: capital-one-platform.trusted
  namespace: capital-one
spec:
  tier: capital-one-platform
  order: 10
  selector: fw-zone == "trusted"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      source:
        selector: fw-zone == "dmz"
      destination: {}
    - action: Allow
      source:
        selector: fw-zone == "trusted"
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Allow
      source: {}
      destination:
        selector: fw-zone == "trusted"
    - action: Allow
      source: {}
      destination:
        selector: fw-zone == "restricted"
    - action: Deny
      source: {}
      destination: {}
  types:
    - Ingress
    - Egress
```

We can see that the ```trusted``` zone is already denying traffic for any potential exfiltration attempts to public internet <br/>
The reason for this is because only workloads labelled ```fw-zone: trusted``` can only contact ```frontend``` workloads that can perform ingress/egress activity against the internet.
<img width="1437" alt="Screenshot 2023-04-05 at 10 59 28" src="https://user-images.githubusercontent.com/126002808/230048603-655d095a-a980-4f49-80fd-a08546e0f6e4.png">

Proof that the traffic from ```microservice2``` is attempting to contact the public internet. <br/>
At this point, we don't know why the network connection was made. That's where we need incident response and forensic capabilities.
<img width="1437" alt="Screenshot 2023-04-05 at 11 05 44" src="https://user-images.githubusercontent.com/126002808/230050128-43a11561-a960-4579-9143-1979aff66767.png">


### Restricted Zone 
Secures sensitive workloads such as a database

```
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: capital-one-platform.restricted
  namespace: capital-one
spec:
  tier: capital-one-platform
  order: 20
  selector: fw-zone == "restricted"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      source:
        selector: fw-zone == "trusted"
      destination: {}
    - action: Allow
      source:
        selector: fw-zone == "restricted"
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Allow
      source: {}
      destination: {}
  types:
    - Ingress
    - Egress
```

Proof that the zone-based architecture was configured for the ```capital-one``` workloads
```
kubectl get networkpolicies.p -n capital-one -l projectcalico.org/tier=capital-one-platform
```
<img width="1437" alt="Screenshot 2023-04-05 at 11 18 02" src="https://user-images.githubusercontent.com/126002808/230052980-289f23c7-68e3-4b1b-b694-e627166aafc8.png">

How the zone-based architecture is represented in the Calico Cloud user interface:

<img width="1437" alt="Screenshot 2023-04-05 at 11 18 50" src="https://user-images.githubusercontent.com/126002808/230053281-95d04550-11f0-4094-864b-f4119e0ed788.png">




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

By default, Calico Cloud hooks-in to 2 IP feeds for known/blacklisted IP CIDRs. <br/>
In our case, we want to see any connections that go to the Tor Network - similar to the Capital One attack.
<img width="1437" alt="Screenshot 2023-04-05 at 11 24 28" src="https://user-images.githubusercontent.com/126002808/230054459-81b1a5ff-0d65-4d10-bfa7-529f7d314174.png">


As you can see in the above .YAML manifest, the ```GlobalThreatFeed``` resource creates another object called a ```globalNetworkSet``` which is just a dynamic list of IP CIDRs associated with Tor Bulk Exit lists.
<img width="1437" alt="Screenshot 2023-04-05 at 11 25 03" src="https://user-images.githubusercontent.com/126002808/230054753-41a7b3fb-7fee-4baf-ac47-38f59feb0750.png">


### GlobalNetworkSet for EC2 Metadata Service
On EC2 instances, 169.254.169.254 is a special IP used to fetch metadata about the instance. <br/>
It may be desirable to detect and prevent access to this IP from containers.
```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: ec2-metadata-service
  labels:
    role: aws-metadata-ip
spec:
  nets:
    - 169.254.169.254
```

### Falco Rule for EC2 Metadata Service

In a local/user rules file, you could override this macro to explicitly enumerate the container images that you want to allow access to EC2 metadata. <br/>
In this main falco rules file, there is no way to know all the containers that should have access, so any container is allowed, by repeating the "container" macro. <br/>
In the overridden macro, the condition would look something like <br/>
<br/>
(container.image.repository = vendor/container-1 or
container.image.repository = vendor/container-2 or ...)

```
- rule: Contact EC2 Instance Metadata Service From Container
  desc: Detect attempts to contact the EC2 Instance Metadata Service from a container
  condition: outbound and fd.sip="169.254.169.254" and container and not ec2_metadata_containers
  output: Outbound connection to EC2 instance metadata service (command=%proc.cmdline pid=%proc.pid connection=%fd.name %container.info image=%container.image.repository:%container.image.tag)
  priority: NOTICE
  enabled: false
  tags: [network, aws, container, mitre_discovery, T1565]
```

## Deny traffic to EC2 metadata service

```
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: nigel-security.block-ec2-metadata
spec:
  tier: nigel-security
  order: 210
  namespaceSelector: 'kubernetes.io/metadata.name == "capital-one"'
  serviceAccountSelector: ''
  egress:
    - action: Deny
      source: {}
      destination:
        selector: role == "aws-metadata-ip"
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Egress
```

![Screenshot 2023-04-05 at 14 15 17](https://user-images.githubusercontent.com/126002808/230091696-d08a99fa-a5a2-4eea-a18c-b6ba7d064fd9.png)



Link back to default Falco rule in GitHub: <br/>
https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml#L2411,L2417

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
