# Lab 1 Istio环境的安装

下载当前最新版本Istio

```bash
curl -L https://istio.io/downloadIstio | sh -
```



```bash
controlplane $ curl -L https://istio.io/downloadIstio | sh -
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   101  100   101    0     0   1530      0 --:--:-- --:--:-- --:--:--  1530
100  4856  100  4856    0     0  55181      0 --:--:-- --:--:-- --:--:-- 55181

Downloading istio-1.16.0 from https://github.com/istio/istio/releases/download/1.16.0/istio-1.16.0-linux-amd64.tar.gz ...

Istio 1.16.0 Download Complete!

Istio has been successfully downloaded into the istio-1.16.0 folder on your system.

Next Steps:
See https://istio.io/latest/docs/setup/install/ to add Istio to your Kubernetes cluster.

To configure the istioctl client tool for your workstation,
add the /root/istio-1.16.0/istio-1.16.0/bin directory to your environment path variable with:
         export PATH="$PATH:/root/istio-1.16.0/istio-1.16.0/bin"

Begin the Istio pre-installation check by running:
         istioctl x precheck 

Need more information? Visit https://istio.io/latest/docs/setup/install/ 
```



根据上述步骤的输出设置环境变量

```bash
export PATH="$PATH:/root/istio-1.16.0/bin"
```



进入目录

```bash
cd istio-1.16.0/
```



检查安装前提条件

```bash
istioctl x precheck 
```



```bash
controlplane $ istioctl x precheck 
✔ No issues found when checking the cluster. Istio is safe to install or upgrade!
  To get started, check out https://istio.io/latest/docs/setup/getting-started/
```



执行安装

```bash
istioctl manifest apply --set profile=demo
```



```bash
controlplane $ istioctl verify-install
0 Istio control planes detected, checking --revision "default" only
error while fetching revision : the server could not find the requested resource
0 Istio injectors detected
Error: could not load IstioOperator from cluster: the server could not find the requested resource. Use --filename
controlplane $ istioctl manifest apply --set profile=demo
This will install the Istio 1.16.0 demo profile with ["Istio core" "Istiod" "Ingress gateways" "Egress gateways"] components into the cluster. Proceed? (y/N) y
✔ Istio core installed                                                                                                                                                                         
✔ Istiod installed                                                                                                                                                                                
✔ Egress gateways installed                                                                                                                                                                       
✔ Ingress gateways installed                                                                                                                                                                      
✔ Installation complete                                                                                                                                                                           Making this installation the default for injection and validation.

Thank you for installing Istio 1.16.  Please take a few minutes to tell us about your install/upgrade experience!  https://forms.gle/99uiMML96AmsXY5d6
```



安装仪表板：

```bash
kubectl apply -f samples/addons
```



```bash
controlplane $ kubectl apply -f samples/addons
serviceaccount/grafana created
configmap/grafana created
service/grafana created
deployment.apps/grafana created
configmap/istio-grafana-dashboards created
configmap/istio-services-grafana-dashboards created
deployment.apps/jaeger created
service/tracing created
service/zipkin created
service/jaeger-collector created
serviceaccount/kiali created
configmap/kiali created
clusterrole.rbac.authorization.k8s.io/kiali-viewer created
clusterrole.rbac.authorization.k8s.io/kiali created
clusterrolebinding.rbac.authorization.k8s.io/kiali created
role.rbac.authorization.k8s.io/kiali-controlplane created
rolebinding.rbac.authorization.k8s.io/kiali-controlplane created
service/kiali created
deployment.apps/kiali created
serviceaccount/prometheus created
configmap/prometheus created
clusterrole.rbac.authorization.k8s.io/prometheus created
clusterrolebinding.rbac.authorization.k8s.io/prometheus created
service/prometheus created
deployment.apps/prometheus created
```



检查 istio 安装版本：

```bash
istioctl version
```



```bash
controlplane $ istioctl version
client version: 1.16.0
control plane version: 1.16.0
data plane version: 1.16.0 (2 proxies)
```



查看 crd：

```bash
kubectl get crd | grep istio
```



```bash
controlplane $ kubectl get crd | grep istio
authorizationpolicies.security.istio.io               2022-12-01T02:49:38Z
destinationrules.networking.istio.io                  2022-12-01T02:49:38Z
envoyfilters.networking.istio.io                      2022-12-01T02:49:39Z
gateways.networking.istio.io                          2022-12-01T02:49:39Z
istiooperators.install.istio.io                       2022-12-01T02:49:39Z
peerauthentications.security.istio.io                 2022-12-01T02:49:39Z
proxyconfigs.networking.istio.io                      2022-12-01T02:49:39Z
requestauthentications.security.istio.io              2022-12-01T02:49:39Z
serviceentries.networking.istio.io                    2022-12-01T02:49:39Z
sidecars.networking.istio.io                          2022-12-01T02:49:39Z
telemetries.telemetry.istio.io                        2022-12-01T02:49:40Z
virtualservices.networking.istio.io                   2022-12-01T02:49:40Z
wasmplugins.extensions.istio.io                       2022-12-01T02:49:40Z
workloadentries.networking.istio.io                   2022-12-01T02:49:40Z
workloadgroups.networking.istio.io                    2022-12-01T02:49:40Z
```



查看 api 资源：

```bash
kubectl api-resources | grep istio
```



```bash
controlplane $ kubectl api-resources | grep istio
wasmplugins                                    extensions.istio.io/v1alpha1           true         WasmPlugin
istiooperators                    iop,io       install.istio.io/v1alpha1              true         IstioOperator
destinationrules                  dr           networking.istio.io/v1beta1            true         DestinationRule
envoyfilters                                   networking.istio.io/v1alpha3           true         EnvoyFilter
gateways                          gw           networking.istio.io/v1beta1            true         Gateway
proxyconfigs                                   networking.istio.io/v1beta1            true         ProxyConfig
serviceentries                    se           networking.istio.io/v1beta1            true         ServiceEntry
sidecars                                       networking.istio.io/v1beta1            true         Sidecar
virtualservices                   vs           networking.istio.io/v1beta1            true         VirtualService
workloadentries                   we           networking.istio.io/v1beta1            true         WorkloadEntry
workloadgroups                    wg           networking.istio.io/v1beta1            true         WorkloadGroup
authorizationpolicies                          security.istio.io/v1beta1              true         AuthorizationPolicy
peerauthentications               pa           security.istio.io/v1beta1              true         PeerAuthentication
requestauthentications            ra           security.istio.io/v1beta1              true         RequestAuthentication
telemetries                       telemetry    telemetry.istio.io/v1alpha1            true         Telemetry
```



查看命名空间：

```bash
kubectl get namespaces 
```



查看 istio 相关pod：

```bash
kubectl get pods -n istio-system
```



```bash
controlplane $ kubectl get pods -n istio-system
NAME                                    READY   STATUS    RESTARTS   AGE
grafana-56bdf8bf85-xm6gn                1/1     Running   0          5m2s
istio-egressgateway-5bdd756dfd-tqmz9    1/1     Running   0          6m31s
istio-ingressgateway-67f7b5f88d-j4v8z   1/1     Running   0          6m31s
istiod-58c6454c57-vq7l4                 1/1     Running   0          6m47s
jaeger-c4fdf6674-ltgkn                  1/1     Running   0          5m2s
kiali-5ff49b9f69-sf42z                  1/1     Running   0          5m2s
prometheus-85949fddb-z57vs              2/2     Running   0          5m1s
```



查看 istio 服务状态：

```bash
kubectl get svc -n istio-system 
```



```bash
controlplane $ kubectl get svc -n istio-system 
NAME                   TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)                                                                      AGE
grafana                ClusterIP      10.104.87.225    <none>        3000/TCP                                                                     5m43s
istio-egressgateway    ClusterIP      10.103.43.184    <none>        80/TCP,443/TCP                                                               7m11s
istio-ingressgateway   LoadBalancer   10.105.52.139    <pending>     15021:30275/TCP,80:31216/TCP,443:31018/TCP,31400:30363/TCP,15443:32013/TCP   7m11s
istiod                 ClusterIP      10.110.235.100   <none>        15010/TCP,15012/TCP,443/TCP,15014/TCP                                        7m28s
jaeger-collector       ClusterIP      10.109.101.148   <none>        14268/TCP,14250/TCP,9411/TCP                                                 5m42s
kiali                  ClusterIP      10.101.69.18     <none>        20001/TCP,9090/TCP                                                           5m42s
prometheus             ClusterIP      10.100.129.105   <none>        9090/TCP                                                                     5m42s
tracing                ClusterIP      10.96.122.246    <none>        80/TCP,16685/TCP                                                             5m42s
zipkin                 ClusterIP      10.106.66.61     <none>        9411/TCP                                                                     5m42s
```



查看各组件状态：

```bash
kubectl get svc,pod,hpa,pdb,Gateway,VirtualService -n istio-system
```



可选步骤

如果因为特殊的国情，导致上一步失败，使用这个步骤：

```bash
wget https://chengzhstor.blob.core.windows.net/k8slab/istio-1.13.2-linux-amd64.tar.gz
tar xf istio-1.13.2-linux-amd64.tar.gz
```



进入下载目录，随着产品的迭代，此处的版本号可能不同，请大家依据屏幕提示进行后两步操作

```bash
cd istio-1.13.2/
```



设置环境变量

```bash
export PATH="$PATH:/root/istio-1.13.2/bin"
```



加载实验脚本目录

```bash
git clone https://github.com/cloudzun/istiolabmanual
```

 



# Lab 2 Bookinfo 示例程序安装

Bookinfo 是 Istio 社区官方推荐的示例应用之一。它可以用来演示多种 Istio 的特性，并且它是一个异构的微服务应用。
本章节大部分实验都和bookinfo有关，因此熟练 快速 准确地部署bookinfo是捣鼓istio重要基本功。



启动自动注入sidecar

```bash
kubectl label namespace default istio-injection=enabled
```



安装 bookinfo

```bash
kubectl apply -f samples/bookinfo/platform/kube/bookinfo.yaml
```



```bash
controlplane $ kubectl label namespace default istio-injection=enabled
namespace/default labeled
controlplane $ kubectl apply -f samples/bookinfo/platform/kube/bookinfo.yaml
service/details created
serviceaccount/bookinfo-details created
deployment.apps/details-v1 created
service/ratings created
serviceaccount/bookinfo-ratings created
deployment.apps/ratings-v1 created
service/reviews created
serviceaccount/bookinfo-reviews created
deployment.apps/reviews-v1 created
deployment.apps/reviews-v2 created
deployment.apps/reviews-v3 created
service/productpage created
serviceaccount/bookinfo-productpage created
deployment.apps/productpage-v1 created
```



确认服务和 pod状态

```bash
kubectl get svc

kubectl get pod
```

此处需要等待大概2分钟，等到所有的pod都ready再进行下一步



```bash
controlplane $ kubectl get svc
NAME          TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
details       ClusterIP   10.103.216.219   <none>        9080/TCP   40s
kubernetes    ClusterIP   10.96.0.1        <none>        443/TCP    17d
productpage   ClusterIP   10.96.27.197     <none>        9080/TCP   39s
ratings       ClusterIP   10.96.54.189     <none>        9080/TCP   39s
reviews       ClusterIP   10.96.4.49       <none>        9080/TCP   39s
controlplane $ 
controlplane $ kubectl get pod
NAME                             READY   STATUS            RESTARTS   AGE
details-v1-5ffd6b64f7-s7src      2/2     Running           0          41s
productpage-v1-979d4d9fc-l97ck   0/2     PodInitializing   0          40s
ratings-v1-5f9699cfdf-465tm      2/2     Running           0          41s
reviews-v1-569db879f5-44qtz      0/2     PodInitializing   0          41s
reviews-v2-65c4dc6fdc-xpb2d      1/2     Running           0          41s
reviews-v3-c9c4fb987-xwdmj       0/2     PodInitializing   0          41s
```



检查sidecar自动注入

```bash
kubectl describe pod productpage-v1-979d4d9fc-l97ck
```

  *重点关注Container部分和Events部分

```bash
controlplane $ kubectl describe pod productpage-v1-979d4d9fc-l97ck
Name:             productpage-v1-979d4d9fc-l97ck
Namespace:        default
Priority:         0
Service Account:  bookinfo-productpage
Node:             controlplane/172.30.1.2
Start Time:       Thu, 01 Dec 2022 03:41:06 +0000
Labels:           app=productpage
                  pod-template-hash=979d4d9fc
                  security.istio.io/tlsMode=istio
                  service.istio.io/canonical-name=productpage
                  service.istio.io/canonical-revision=v1
                  version=v1
Annotations:      cni.projectcalico.org/containerID: 370eb16f6bbdde82e05db1b246ca9c9b7d624ea6da7725f2dd8c994833959c8b
                  cni.projectcalico.org/podIP: 192.168.0.7/32
                  cni.projectcalico.org/podIPs: 192.168.0.7/32
                  kubectl.kubernetes.io/default-container: productpage
                  kubectl.kubernetes.io/default-logs-container: productpage
                  prometheus.io/path: /stats/prometheus
                  prometheus.io/port: 15020
                  prometheus.io/scrape: true
                  sidecar.istio.io/status:
                    {"initContainers":["istio-init"],"containers":["istio-proxy"],"volumes":["workload-socket","credential-socket","workload-certs","istio-env...
Status:           Running
IP:               192.168.0.7
IPs:
  IP:           192.168.0.7
Controlled By:  ReplicaSet/productpage-v1-979d4d9fc
Init Containers:
  istio-init:
    Container ID:  containerd://0ed6fa7fc4424ca8e438b539a789f0d0f1cf83db44c51000f69e8ffc782f0ebd
    Image:         docker.io/istio/proxyv2:1.16.0
    Image ID:      docker.io/istio/proxyv2@sha256:f6f97fa4fb77a3cbe1e3eca0fa46bd462ad6b284c129cf57bf91575c4fb50cf9
    Port:          <none>
    Host Port:     <none>
    Args:
      istio-iptables
      -p
      15001
      -z
      15006
      -u
      1337
      -m
      REDIRECT
      -i
      *
      -x
      
      -b
      *
      -d
      15090,15021,15020
      --log_output_level=default:info
    State:          Terminated
      Reason:       Completed
      Exit Code:    0
      Started:      Thu, 01 Dec 2022 03:41:18 +0000
      Finished:     Thu, 01 Dec 2022 03:41:18 +0000
    Ready:          True
    Restart Count:  0
    Limits:
      cpu:     2
      memory:  1Gi
    Requests:
      cpu:        10m
      memory:     40Mi
    Environment:  <none>
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-n7v78 (ro)
Containers:
  productpage:
    Container ID:   containerd://8a0f4d1e955d4b0c5349d5bc56467d6bb135bf06031dc397d483dda64fcd9e89
    Image:          docker.io/istio/examples-bookinfo-productpage-v1:1.17.0
    Image ID:       docker.io/istio/examples-bookinfo-productpage-v1@sha256:6668bcf42ef0afb89d0ccd378905c761eab0f06919e74e178852b58b4bbb29c5
    Port:           9080/TCP
    Host Port:      0/TCP
    State:          Running
      Started:      Thu, 01 Dec 2022 03:42:06 +0000
    Ready:          True
    Restart Count:  0
    Environment:    <none>
    Mounts:
      /tmp from tmp (rw)
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-n7v78 (ro)
  istio-proxy:
    Container ID:  containerd://01ec70eef67d93f2b67b0c274edf98c6c14718a61fe8e97137f792ec3023105b
    Image:         docker.io/istio/proxyv2:1.16.0
    Image ID:      docker.io/istio/proxyv2@sha256:f6f97fa4fb77a3cbe1e3eca0fa46bd462ad6b284c129cf57bf91575c4fb50cf9
    Port:          15090/TCP
    Host Port:     0/TCP
    Args:
      proxy
      sidecar
      --domain
      $(POD_NAMESPACE).svc.cluster.local
      --proxyLogLevel=warning
      --proxyComponentLogLevel=misc:error
      --log_output_level=default:info
      --concurrency
      2
    State:          Running
      Started:      Thu, 01 Dec 2022 03:42:06 +0000
    Ready:          True
    Restart Count:  0
    Limits:
      cpu:     2
      memory:  1Gi
    Requests:
      cpu:      10m
      memory:   40Mi
    Readiness:  http-get http://:15021/healthz/ready delay=1s timeout=3s period=2s #success=1 #failure=30
    Environment:
      JWT_POLICY:                    third-party-jwt
      PILOT_CERT_PROVIDER:           istiod
      CA_ADDR:                       istiod.istio-system.svc:15012
      POD_NAME:                      productpage-v1-979d4d9fc-l97ck (v1:metadata.name)
      POD_NAMESPACE:                 default (v1:metadata.namespace)
      INSTANCE_IP:                    (v1:status.podIP)
      SERVICE_ACCOUNT:                (v1:spec.serviceAccountName)
      HOST_IP:                        (v1:status.hostIP)
      PROXY_CONFIG:                  {}
                                     
      ISTIO_META_POD_PORTS:          [
                                         {"containerPort":9080,"protocol":"TCP"}
                                     ]
      ISTIO_META_APP_CONTAINERS:     productpage
      ISTIO_META_CLUSTER_ID:         Kubernetes
      ISTIO_META_INTERCEPTION_MODE:  REDIRECT
      ISTIO_META_WORKLOAD_NAME:      productpage-v1
      ISTIO_META_OWNER:              kubernetes://apis/apps/v1/namespaces/default/deployments/productpage-v1
      ISTIO_META_MESH_ID:            cluster.local
      TRUST_DOMAIN:                  cluster.local
    Mounts:
      /etc/istio/pod from istio-podinfo (rw)
      /etc/istio/proxy from istio-envoy (rw)
      /var/lib/istio/data from istio-data (rw)
      /var/run/secrets/credential-uds from credential-socket (rw)
      /var/run/secrets/istio from istiod-ca-cert (rw)
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-n7v78 (ro)
      /var/run/secrets/tokens from istio-token (rw)
      /var/run/secrets/workload-spiffe-credentials from workload-certs (rw)
      /var/run/secrets/workload-spiffe-uds from workload-socket (rw)
Conditions:
  Type              Status
  Initialized       True 
  Ready             True 
  ContainersReady   True 
  PodScheduled      True 
Volumes:
  workload-socket:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:     
    SizeLimit:  <unset>
  credential-socket:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:     
    SizeLimit:  <unset>
  workload-certs:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:     
    SizeLimit:  <unset>
  istio-envoy:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:     Memory
    SizeLimit:  <unset>
  istio-data:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:     
    SizeLimit:  <unset>
  istio-podinfo:
    Type:  DownwardAPI (a volume populated by information about the pod)
    Items:
      metadata.labels -> labels
      metadata.annotations -> annotations
  istio-token:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  43200
  istiod-ca-cert:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      istio-ca-root-cert
    Optional:  false
  tmp:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:     
    SizeLimit:  <unset>
  kube-api-access-n7v78:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    ConfigMapOptional:       <nil>
    DownwardAPI:             true
QoS Class:                   Burstable
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type     Reason     Age                From               Message
  ----     ------     ----               ----               -------
  Normal   Scheduled  96s                default-scheduler  Successfully assigned default/productpage-v1-979d4d9fc-l97ck to controlplane
  Normal   Pulling    95s                kubelet            Pulling image "docker.io/istio/proxyv2:1.16.0"
  Normal   Pulled     85s                kubelet            Successfully pulled image "docker.io/istio/proxyv2:1.16.0" in 10.334996634s
  Normal   Created    85s                kubelet            Created container istio-init
  Normal   Started    84s                kubelet            Started container istio-init
  Normal   Pulling    84s                kubelet            Pulling image "docker.io/istio/examples-bookinfo-productpage-v1:1.17.0"
  Normal   Pulled     37s                kubelet            Successfully pulled image "docker.io/istio/examples-bookinfo-productpage-v1:1.17.0" in 46.9444707s
  Normal   Created    37s                kubelet            Created container productpage
  Normal   Started    36s                kubelet            Started container productpage
  Normal   Pulled     36s                kubelet            Container image "docker.io/istio/proxyv2:1.16.0" already present on machine
  Normal   Created    36s                kubelet            Created container istio-proxy
  Normal   Started    36s                kubelet            Started container istio-proxy
  Warning  Unhealthy  33s (x4 over 35s)  kubelet            Readiness probe failed: Get "http://192.168.0.7:15021/healthz/ready": dial tcp 192.168.0.7:15021: connect: connection refused
```



检查productpage页面访问

```bash
kubectl exec -it $(kubectl get pod -l app=ratings -o jsonpath='{.items[0].metadata.name}') -c ratings -- curl productpage:9080/productpage | grep -o "<title>.*</title>"
```



```bash
controlplane $ kubectl exec -it $(kubectl get pod -l app=ratings -o jsonpath='{.items[0].metadata.name}') -c ratings -- curl productpage:9080/productpage | grep -o "<title>.*</title>"
<title>Simple Bookstore App</title>
```



启动默认网关

```bash
kubectl apply -f samples/bookinfo/networking/bookinfo-gateway.yaml
```



使用默认目标规则

```bash
kubectl apply -f samples/bookinfo/networking/destination-rule-all.yaml
```



针对productpage启用nodeport，并确认对外访问路径和端口

```bash
export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n istio-system -o jsonpath='{.items[0].status.hostIP}')
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')
export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
echo $GATEWAY_URL
echo http://$GATEWAY_URL/productpage
```

 

```bash
controlplane $ kubectl apply -f samples/bookinfo/networking/destination-rule-all.yaml
destinationrule.networking.istio.io/productpage created
destinationrule.networking.istio.io/reviews created
destinationrule.networking.istio.io/ratings created
destinationrule.networking.istio.io/details created
controlplane $ export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n istio-system -o jsonpath='{.items[0].status.hostIP}')
controlplane $ export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')
controlplane $ export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
controlplane $ export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
controlplane $ echo $GATEWAY_URL
172.30.2.2:30175
controlplane $ echo http://$GATEWAY_URL/productpage
http://172.30.2.2:30175/productpage
controlplane $ 
```





# Lab 3 服务路由和流量管理

## 1.动态路由

（可选）启用默认目标规则

```bash
kubectl apply -f samples/bookinfo/networking/destination-rule-all.yaml
```



查看目标规则

```bash
nano samples/bookinfo/networking/destination-rule-all.yaml
```



```yaml
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: productpage
spec:
  host: productpage
  subsets:
  - name: v1
    labels:
      version: v1
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews
spec:
  host: reviews
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
  - name: v3
    labels:
      version: v3
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: ratings
spec:
  host: ratings
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
  - name: v2-mysql
    labels:
      version: v2-mysql
  - name: v2-mysql-vm
    labels:
      version: v2-mysql-vm
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: details
spec:
  host: details
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
---
```



创建将review流量都指向v1虚拟服务

```bash
kubectl apply -f samples/bookinfo/networking/virtual-service-all-v1.yaml
```



查看该虚拟服务

```
nano samples/bookinfo/networking/virtual-service-all-v1.yaml
```



这个配置文件明确定义了任何情况下只呈现v1版本的reviews

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: productpage
spec:
  hosts:
  - productpage
  http:
  - route:
    - destination:
        host: productpage
        subset: v1
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews
spec:
  hosts:
  - reviews
  http:
  - route:
    - destination:
        host: reviews
        subset: v1
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: ratings
spec:
  hosts:
  - ratings
  http:
  - route:
    - destination:
        host: ratings
        subset: v1
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: details
spec:
  hosts:
  - details
  http:
  - route:
    - destination:
        host: details
        subset: v1
---
```



使用浏览器查看效果,	即使反复F5，也是无星星版

![image-20221201115502082](manual.assets/image-20221201115502082.png)

创建将登录用户的review流量都指向v2的虚拟服务

```bash
kubectl apply -f  samples/bookinfo/networking/virtual-service-reviews-test-v2.yaml
```



Jason同志应该可以看到黑星星

![image-20221201115541479](manual.assets/image-20221201115541479.png)

查看该虚拟服务

```bash
nano samples/bookinfo/networking/virtual-service-reviews-test-v2.yaml
```

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews
spec:
  hosts:
    - reviews
  http:
  - match:
    - headers:
        end-user:
          exact: jason
    route:
    - destination:
        host: reviews
        subset: v2
  - route:
    - destination:
        host: reviews
        subset: v1
```



清理环境

```bash
kubectl delete -f samples/bookinfo/networking/virtual-service-all-v1.yaml
kubectl delete -f samples/bookinfo/networking/virtual-service-reviews-test-v2.yaml
```



## 2.流量转移

（可选）启用默认目标规则

```bash
kubectl apply -f samples/bookinfo/networking/destination-rule-all.yaml
```



使用浏览器查看页面效果，主要是关注reviews的版本



将所有流量指向reviews:v1

```bash
kubectl apply -f samples/bookinfo/networking/virtual-service-all-v1.yaml
```

使用浏览器查看页面效果，主要是关注reviews的版本



将50% 的流量从 reviews:v1 转移到 reviews:v3

```bash
kubectl apply -f samples/bookinfo/networking/virtual-service-reviews-50-v3.yaml
```



查看该虚拟服务

```bash
nano samples/bookinfo/networking/virtual-service-reviews-50-v3.yaml
```

使用浏览器查看页面效果，主要是关注reviews的版本



将 100% 的流量路由到 reviews:v3

```bash
kubectl apply -f samples/bookinfo/networking/virtual-service-reviews-v3.yaml
```



查看该虚拟服务

```bash
nano samples/bookinfo/networking/virtual-service-reviews-v3.yaml
```



使用浏览器查看页面效果，主要是关注reviews的版本

清理

```bash
kubectl delete -f samples/bookinfo/networking/virtual-service-all-v1.yaml
```



## 3.网关

查看现有网关

```bash
kubectl get gw
```



增加网关

```bash
kubectl apply -f istiolabmanual/gateway.yaml 
```



查看现有网关

```bash
kubectl get gw
```



查看该网关配置

```bash
kubectl describe gw test-gateway
```



增加虚拟服务

```bash
kubectl apply -f istiolabmanual/virtualservice.yaml
```



查看虚拟服务

```bash
kubectl get vs
```



查看该虚拟服务配置

```bash
kubectl describe vs test-gateway
```

随后使用浏览器访问/details/0 和 /health，检查效果



清理环境

```bash
kubectl delete -f istiolabmanual/gateway.yaml 
kubectl delete -f istiolabmanual/virtualservice.yaml
```



## 4.服务入口

安装sleep应用

```bash
kubectl apply -f samples/sleep/sleep.yaml
```



查看pod

```bash
kubectl  get pod 
```



设置source_pod 变量

```bash
export SOURCE_POD=$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})
```



查看出站访问效果

```bash
kubectl exec -it $SOURCE_POD -c sleep -- curl http://httpbin.org/headers
```



关闭默认出站访问

```bash
istioctl install  --set meshConfig.outboundTrafficPolicy.mode=REGISTRY_ONLY -y
```



查看出站访问效果

```bash
kubectl exec -it $SOURCE_POD -c sleep -- curl http://httpbin.org/headers
```



创建指向 httpbin.org 的ServiceEntry

```bash
kubectl apply -f istiolabmanual/serviceentry.yaml
```



查看ServiceEntry

```bash
kubectl get se
```



稍等数秒钟之后，再次查看出站访问效果

```bash
kubectl exec -it $SOURCE_POD -c sleep -- curl http://httpbin.org/ip
```



查看该ServiceEntry配置

```bash
kubectl describe se httpbin-ext
```



清理

```bash
kubectl delete -f samples/sleep/sleep.yaml
kubectl delete -f istiolabmanual/serviceentry.yaml
istioctl install --set profile=demo -y
```



## 5.Ingress

创建httpbin服务

```bash
kubectl apply -f samples/httpbin/httpbin.yaml
```



查看pod 

```bash
kubectl get pods
```



查看ingressgateway

```bash
kubectl get svc istio-ingressgateway -n istio-system
```



设置ingress主机和端口变量

```bash
export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n istio-system -o jsonpath='{.items[0].status.hostIP}')
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')
export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
export TCP_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="tcp")].nodePort}')
```



创建ingress gateway，定义接入点 

```bash
kubectl apply -f  istiolabmanual/ingressgateway.yaml 
```



创建virtual service 定义路由规则 

```bash
kubectl apply -f istiolabmanual/ingressvs.yaml 
```



查看Virtual Service信息，重点关注服务 网关和主机的绑定关系

```bash
kubectl get vs
```



访问已发布的httpin 接口

```bash
curl -I -HHost:httpbin.example.com http://$INGRESS_HOST:$INGRESS_PORT/status/200

curl -I -HHost:httpbin.example.com http://$INGRESS_HOST:$INGRESS_PORT/delay/2
```



访问未经定义的目标

```bash
curl -I -HHost:httpbin.example.com http://$INGRESS_HOST:$INGRESS_PORT/headers
```



设置规则将headers服务发布到外网 

```bash
kubectl apply -f istiolabmanual/ingressgateway2.yaml 
```



使用浏览器加 /headers 在外网进行访问



查看Virtual Service信息，重点关注服务 网关和主机的绑定关系

```bash
kubectl get vs
```



清理资源

```bash
kubectl delete gateway httpbin-gateway
kubectl delete virtualservice httpbin
kubectl delete --ignore-not-found=true -f samples/httpbin/httpbin.yaml
```



## 6.Egress

查看istio 系统服务，确认egress gateway 组件正常运行

```bash
kubectl get svc -n istio-system
```



查看istio 系统pod

```bash
kubectl get pod -n istio-system
```



安装sleep应用

```bash
kubectl apply -f samples/sleep/sleep.yaml
```



设置source_pod 变量

```bash
export SOURCE_POD=$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})
```



为外部httpbin服务创建service entry

```bash
kubectl  apply -f  istiolabmanual/egressse.yaml 
```



检查Service Entry

```bash
kubectl get se
```



从sleep上访问外网

```bash
kubectl exec -it $SOURCE_POD -c sleep -- curl http://httpbin.org/ip
```



检查sidecar里的proxy日志

```bash
kubectl logs $SOURCE_POD -c istio-proxy | tail
```



注意观察，此处的`upstream_cluster："outbound|80||httpbin.org"`



查看Virtual Service 和 Destination Rule信息

```bash
kubectl get vs

kubectl get dr
```



创建egress gateway

```bash
kubectl  apply -f  istiolabmanual/egressgw.yaml 
```



查看gateway

```bash
kubectl get gw
```



创建virtual service，将流量引导到egress gateway

```bash
kubectl  apply -f  istiolabmanual/egressvs.yaml 
```



查看Virtual Service 和Destination Rule信息

```bash
kubectl get vs
kubectl get dr
```

从sleep上访问外网

```bash
kubectl exec -it $SOURCE_POD -c sleep -- curl http://httpbin.org/ip
```

 	注意：此处的ip地址发生了变化



检查sidecar里的proxy日志，观察新的条目

```bash
kubectl logs $SOURCE_POD -c istio-proxy | tail
```

注意观察，启用了`egress gateway`之后此处的`upstream_cluster："outbound|80|httpbin|istio-egressgateway.istio-system.svc.cluster.local"`



清理

```bash
kubectl delete -f samples/sleep/sleep.yaml
kubectl delete -f  istiolabmanual/egressse.yaml 
kubectl delete -f istiolabmanual/egressgw.yaml
kubectl delete -f istiolabmanual/egressvs.yaml 
```



# Lab 4 弹性能力

## 1.超时重试

（可选）加载default destination rules.

```bash
kubectl apply -f samples/bookinfo/networking/destination-rule-all.yaml
```



将review指向v2版本

```bash
kubectl apply -f istiolabmanual/reviewsv2.yaml 
```



查看bookinfo页面，看黑星星



给ratings 服务添加延迟

```bash
kubectl apply -f istiolabmanual/delay.yaml 
```



查看bookinfo页面观察延迟
  会观察到页面需要大约2s才能加载完成 



给reviews 服务添加超时策略

```bash
kubectl apply -f istiolabmanual/timeout.yaml 
```



查看bookinfo页面观察快速失败
  延时设置为2s，但是我们的超时是1s，所以就可耻地失败了



给ratings 服务添加重试策略

```bash
kubectl apply -f istiolabmanual/retry.yaml 
```

 	

从bookinfo页面上刷新一次，查看日志看是否有两次重试

```bash
kubectl logs -f ratings-v1-xxxxx -c istio-proxy
```



注意观察日志中的两个条目的`path`和`start_time`



清理

```bash
kubectl delete -f samples/bookinfo/networking/virtual-service-all-v1.yaml
```



## 2.熔断

部署httpin服务

```bash
kubectl apply -f samples/httpbin/httpbin.yaml
```



在服务的DestinationRule 中添加熔断设置

```bash
kubectl apply -f istiolabmanual/circuitbreaking.yaml 
```



查看DestinationRule 

```bash
kubectl describe dr httpbin 
```



安装测试工具

```bash
kubectl apply -f samples/httpbin/sample-client/fortio-deploy.yaml
```



查看正常访问结果

```bash
FORTIO_POD=$(kubectl get pods -lapp=fortio -o 'jsonpath={.items[0].metadata.name}')
kubectl exec -it "$FORTIO_POD"  -c fortio -- /usr/bin/fortio load -curl http://httpbin:8000/get
```



触发熔断  2个并发，执行20次

```bash
kubectl exec -it "$FORTIO_POD"  -c fortio -- /usr/bin/fortio load -c 2 -qps 0 -n 20 -loglevel Warning http://httpbin:8000/get
```



触发熔断 again 3个并发，执行30次

```bash
kubectl exec -it "$FORTIO_POD"  -c fortio -- /usr/bin/fortio load -c 3 -qps 0 -n 30 -loglevel Warning http://httpbin:8000/get
```



查看熔断指标

```bash
kubectl exec "$FORTIO_POD" -c istio-proxy -- pilot-agent request GET stats | grep httpbin | grep pending
```

 	`overflow`即是被熔断的访问次数



清理

```bash
kubectl delete destinationrule httpbin
kubectl delete deploy httpbin fortio-deploy
kubectl delete svc httpbin fortio
```

 

# Lab 5 调试

## 1.故障注入

启用路由策略
kubectl apply -f samples/bookinfo/networking/virtual-service-all-v1.yaml
kubectl apply -f samples/bookinfo/networking/virtual-service-reviews-test-v2.yaml

分别使用匿名用户和jason查看bookinfo界面
  Jason同学黑星星
  普通群众无星星

注入延时故障
kubectl apply -f samples/bookinfo/networking/virtual-service-ratings-test-delay.yaml

分别使用匿名用户和jason查看bookinfo界面
 Jason 踩坑了 
 普通群众情绪稳定

注入异常中断故障
kubectl apply -f samples/bookinfo/networking/virtual-service-ratings-test-abort.yaml

分别使用匿名用户和jason查看bookinfo界面 
  Jason 中招 
  普通群众没事

清理环境
kubectl delete -f samples/bookinfo/networking/virtual-service-all-v1.yaml

## 2.流量镜像

创建httpbin-v1 和 httpbin-v2
kubectl apply -f istiolabmanual/httpbin-v1.yaml  
kubectl apply -f istiolabmanual/httpbin-v2.yaml 

发布服务
kubectl apply -f istiolabmanual/httpbinsvc.yaml

启动sleep服务
kubectl apply -f samples/sleep/sleep.yaml

设置路由规则
kubectl apply -f istiolabmanual/httpbinvs.yaml 

使用sleep访问服务
export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})
kubectl exec -it $SLEEP_POD -c sleep -- sh -c 'curl  http://httpbin:8000/headers' | python3 -m json.tool

查看v1和v2的日志
export V1_POD=$(kubectl get pod -l app=httpbin,version=v1 -o jsonpath={.items..metadata.name})
kubectl logs -f $V1_POD -c httpbin

export V2_POD=$(kubectl get pod -l app=httpbin,version=v2 -o jsonpath={.items..metadata.name})
kubectl logs -f $V2_POD -c httpbin

设置镜像规则
kubectl apply -f istiolabmanual/mirror.yaml --validate=false

使用sleep访问服务
export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})
kubectl exec -it $SLEEP_POD -c sleep -- sh -c 'curl  http://httpbin:8000/headers' | python3 -m json.tool

查看v1和v2的日志
export V1_POD=$(kubectl get pod -l app=httpbin,version=v1 -o jsonpath={.items..metadata.name})
kubectl logs -f $V1_POD -c httpbin

export V2_POD=$(kubectl get pod -l app=httpbin,version=v2 -o jsonpath={.items..metadata.name})
kubectl logs -f $V2_POD -c httpbin

清理
kubectl delete virtualservice httpbin
kubectl delete destinationrule httpbin
kubectl delete deploy httpbin-v1 httpbin-v2 sleep
kubectl delete svc httpbin 



# Lab 6 验证：配置TLS安全网关

## 1.为单Host配置 TLS ingress gateway

创建根证书和为证书签名的私钥
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -subj '/O=example Inc./CN=example.com' -keyout example.com.key -out example.com.crt

为httpbin.example.com创建证书和私钥：
openssl req -out httpbin.example.com.csr -newkey rsa:2048 -nodes -keyout httpbin.example.com.key -subj "/CN=httpbin.example.com/O=httpbin organization"
openssl x509 -req -sha256 -days 365 -CA example.com.crt -CAkey example.com.key -set_serial 0 -in httpbin.example.com.csr -out httpbin.example.com.crt

启动 httpbin 用例
kubectl apply -f istiolabmanual/sdshttpbin.yaml 

为ingress gateway创建 secret
kubectl create -n istio-system secret tls httpbin-credential --key=httpbin.example.com.key --cert=httpbin.example.com.crt

创建 Gateway ，可以打开 yaml文件重点关注servers以及TLS部分的定义
kubectl apply -f istiolabmanual/sdsgateway.yaml

配置网关的ingress traffic routes 定义相应的虚拟服务
kubectl apply -f istiolabmanual/sdsvirtualserver.yaml 

设置ingress主机和端口变量
export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n istio-system -o jsonpath='{.items[0].status.hostIP}')
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')
export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
export TCP_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="tcp")].nodePort}')

发送HTTPS请求访问httpbin服务
curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert example.com.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
    此处应该有茶壶

回滚日志查看 TSL 握手过程

删除网关的secret并创建一个新 secret以更改ingress gateway的凭据
kubectl -n istio-system delete secret httpbin-credential

mkdir new_certificates
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -subj '/O=example Inc./CN=example.com' -keyout new_certificates/example.com.key -out new_certificates/example.com.crt
openssl req -out new_certificates/httpbin.example.com.csr -newkey rsa:2048 -nodes -keyout new_certificates/httpbin.example.com.key -subj "/CN=httpbin.example.com/O=httpbin organization"
openssl x509 -req -sha256 -days 365 -CA new_certificates/example.com.crt -CAkey new_certificates/example.com.key -set_serial 0 -in new_certificates/httpbin.example.com.csr -out new_certificates/httpbin.example.com.crt
kubectl create -n istio-system secret tls httpbin-credential \
--key=new_certificates/httpbin.example.com.key \
--cert=new_certificates/httpbin.example.com.crt

使用新证书进行访问
curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert new_certificates/example.com.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
    此处还是有茶壶

尝试使用旧证书访问
curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert example.com.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
    吃瘪

## 2.为多Host配置TLS ingress gateway

重新创建httpbin凭据
kubectl -n istio-system delete secret httpbin-credential
kubectl create -n istio-system secret tls httpbin-credential \
--key=httpbin.example.com.key \
--cert=httpbin.example.com.crt

启用helloworld-v1样例
kubectl apply -f istiolabmanual/helloworld-v1.yaml

为helloworld-v1.example.com创建证书和私钥：
openssl req -out helloworld-v1.example.com.csr -newkey rsa:2048 -nodes -keyout helloworld-v1.example.com.key -subj "/CN=helloworld-v1.example.com/O=helloworld organization"
openssl x509 -req -sha256 -days 365 -CA example.com.crt -CAkey example.com.key -set_serial 1 -in helloworld-v1.example.com.csr -out helloworld-v1.example.com.crt

创建helloworld-credential secret
kubectl create -n istio-system secret tls helloworld-credential --key=helloworld-v1.example.com.key --cert=helloworld-v1.example.com.crt

创建指向两个服务的gateway
kubectl apply -f istiolabmanual/mygatewayv1.yaml

创建helloworld-v1的vs
kubectl apply -f istiolabmanual/helloworld-v1vs.yaml

向v1发起访问
curl -v -HHost:helloworld-v1.example.com --resolve "helloworld-v1.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert example.com.crt "https://helloworld-v1.example.com:$SECURE_INGRESS_PORT/hello"
    此处收获HTTP/2 200

向httpbin.example.com发起访问
curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert example.com.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
    此处还是有茶壶

## 3.配置交互TLS ingress gateway

更新证书
kubectl -n istio-system delete secret httpbin-credential
kubectl create -n istio-system secret generic httpbin-credential --from-file=tls.key=httpbin.example.com.key \
--from-file=tls.crt=httpbin.example.com.crt --from-file=ca.crt=example.com.crt

把mygateway切换到mutual模式
kubectl apply -f istiolabmanual/mygatewayv2.yaml


尝试使用之前的方式进行访问
curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert example.com.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
    吃瘪

生成新的客户端证书和私钥
openssl req -out client.example.com.csr -newkey rsa:2048 -nodes -keyout client.example.com.key -subj "/CN=client.example.com/O=client organization"
openssl x509 -req -sha256 -days 365 -CA example.com.crt -CAkey example.com.key -set_serial 1 -in client.example.com.csr -out client.example.com.crt

向httpbin.example.com发起访问
curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
--cacert example.com.crt --cert client.example.com.crt --key client.example.com.key \
"https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
    此处还是有茶壶

清理环境
kubectl delete gateway mygateway
kubectl delete virtualservice httpbin
kubectl delete --ignore-not-found=true -n istio-system secret httpbin-credential \
helloworld-credential
kubectl delete --ignore-not-found=true virtualservice helloworld-v1

rm -rf example.com.crt example.com.key httpbin.example.com.crt httpbin.example.com.key httpbin.example.com.csr helloworld-v1.example.com.crt helloworld-v1.example.com.key helloworld-v1.example.com.csr client.example.com.crt client.example.com.csr client.example.com.key ./new_certificates

kubectl delete deployment --ignore-not-found=true httpbin helloworld-v1
kubectl delete service --ignore-not-found=true httpbin helloworld-v1



# Lab 7 认证：为应用生成双向TLS

创建两个名称空间foo和bar，并在它们两个上部署httpbin 和 sleep 并启用sidecar注入：
kubectl create ns foo
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n foo
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n foo
kubectl create ns bar
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n bar
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n bar

创建另一个 legacy 名称空间，不启用sidecar注入的情况下部署sleep：
kubectl create ns legacy
kubectl apply -f samples/httpbin/httpbin.yaml -n legacy
kubectl apply -f samples/sleep/sleep.yaml -n legacy

查看这三个名称空间的相互访问情况
for from in "foo" "bar" "legacy"; do for to in "foo" "bar"; do kubectl exec $(kubectl get pod -l app=sleep -n ${from} -o jsonpath={.items..metadata.name}) -c sleep -n ${from} -- curl http://httpbin.${to}:8000/ip -s -o /dev/null -w "sleep.${from} to httpbin.${to}: %{http_code}\n"; done; done
  两两互通，和谐

检查authentication policies 和 destination rules
kubectl get peerauthentication --all-namespaces

kubectl get destinationrule --all-namespaces

在整个网格上启用PERMISSIVE模式的认证策略
kubectl apply -n istio-system -f istiolabmanual/mtlspermissive.yaml 

查看这三个名称空间的相互访问情况
for from in "foo" "bar" "legacy"; do for to in "foo" "bar"; do kubectl exec $(kubectl get pod -l app=sleep -n ${from} -o jsonpath={.items..metadata.name}) -c sleep -n ${from} -- curl http://httpbin.${to}:8000/ip -s -o /dev/null -w "sleep.${from} to httpbin.${to}: %{http_code}\n"; done; done
  还是很和谐，因为策略比较宽松

在整个网格上启用STRICT模式的认证策略
kubectl  apply -n istio-system -f istiolabmanual/mtlsstrict.yaml 

查看这三个名称空间的相互访问情况
for from in "foo" "bar" "legacy"; do for to in "foo" "bar"; do kubectl exec $(kubectl get pod -l app=sleep -n ${from} -o jsonpath={.items..metadata.name}) -c sleep -n ${from} -- curl http://httpbin.${to}:8000/ip -s -o /dev/null -w "sleep.${from} to httpbin.${to}: %{http_code}\n"; done; done
  策略一旦收紧，legacy 被发现是裸泳的了，悲剧

重建legacy 名称空间的服务，请启用sidecar注入
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n legacy
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n legacy

查看这三个名称空间的相互访问情况
for from in "foo" "bar" "legacy"; do for to in "foo" "bar"; do kubectl exec $(kubectl get pod -l app=sleep -n ${from} -o jsonpath={.items..metadata.name}) -c sleep -n ${from} -- curl http://httpbin.${to}:8000/ip -s -o /dev/null -w "sleep.${from} to httpbin.${to}: %{http_code}\n"; done; done
  注入sidecar之后，legacy又可以和小伙伴们一起玩耍了

清理
kubectl delete peerauthentication --all-namespaces –all
kubectl delete ns foo bar legacy



# Lab 8 授权：实现JWT身份的认证和授权

创建包含 httpbin 和sleep样例的名称空间foo
kubectl create ns foo
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n foo
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n foo

检查httpbin和sleep的通讯情况
kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl http://httpbin.foo:8000/ip -s -o /dev/null -w "%{http_code}\n"
  一切正常，本来就是by default的吗

为httpbin创建 request authentication policy
kubectl apply -f istiolabmanual/jwtra.yaml

检查持有无效JWT的访问
kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/headers" -s -o /dev/null -H "Authorization: Bearer invalidToken" -w "%{http_code}\n"
  理应不能访问，401没毛病

检查不持有JWT的访问， 
kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/headers" -s -o /dev/null -w "%{http_code}\n"
  这居然也能成功，尴尬

在foo上启用 authorization policy
kubectl apply -f istiolabmanual/jwtap.yaml 

设置指向JWT的Token变量
TOKEN=$(curl https://raw.githubusercontent.com/istio/istio/release-1.5/security/tools/jwt/samples/demo.jwt -s) && echo $TOKEN | cut -d '.' -f2 - | base64 --decode -

使用有效JWT进行访问
kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/headers" -s -o /dev/null -H "Authorization: Bearer $TOKEN" -w "%{http_code}\n"

再次验证不持有JWT的访问
kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/headers" -s -o /dev/null -w "%{http_code}\n"
  授权策略启用之后，就没办法浑水摸鱼了，403了

清理环境
kubectl delete namespace foo



# Lab 9 监控

模拟一次页面访问,为了防止被不必要的katacode页面元素“污染“，我们最好从内部用命令行执行一次curl访问
kubectl get svc

curl http://10.109.209.72:9080/productpage

查看istio proxy日志
kubectl get pods

kubectl logs -f productpage-xxx istio-proxy

观察到两个outbond条目，分别指向details和reviews，还有一个inbound条目，指向productpage

为获取更多信息，设置日志以JSON格式显式
istioctl manifest apply --set profile=demo --set values.meshConfig.accessLogFile="/dev/stdout" --set values.meshConfig.accessLogEncoding=JSON

（可选）查看日志设置
kubectl describe configmap istio -n istio-system | less
  配置文件有以下输出
  accessLogEncoding: JSON
  accessLogFile: /dev/stdout

再次查看istio proxy日志
kubectl logs -f productpage-xxx istio-proxy

分别指向details和reviews 的outbound条目
{"downstream_remote_address":"10.40.0.12:41654","authority":"details:9080","path":"/details/0","protocol":"HTTP/1.1","upstream_service_time":"9","upstream_local_address":"10.40.0.12:48508","duration":"15","upstream_transport_failure_reason":"-","route_name":"default","downstream_local_address":"10.99.18.67:9080","user_agent":"curl/7.47.0","response_code":"200","response_flags":"-","start_time":"2020-05-15T06:30:26.459Z","method":"GET","request_id":"e2de9f03-38ac-924d-ae2b-176d868c56ab","upstream_host":"10.40.0.8:9080","x_forwarded_for":"-","requested_server_name":"-","bytes_received":"0","istio_policy_status":"-","bytes_sent":"178","upstream_cluster":"outbound|9080||details.default.svc.cluster.local"}

{"upstream_cluster":"outbound|9080||reviews.default.svc.cluster.local","downstream_remote_address":"10.40.0.12:43866","authority":"reviews:9080","path":"/reviews/0","protocol":"HTTP/1.1","upstream_service_time":"1786","upstream_local_address":"10.40.0.12:36048","duration":"1787","upstream_transport_failure_reason":"-","route_name":"default","downstream_local_address":"10.98.163.167:9080","user_agent":"curl/7.47.0","response_code":"200","response_flags":"-","start_time":"2020-05-15T06:30:26.480Z","method":"GET","request_id":"e2de9f03-38ac-924d-ae2b-176d868c56ab","upstream_host":"10.40.0.11:9080","x_forwarded_for":"-","requested_server_name":"-","bytes_received":"0","istio_policy_status":"-","bytes_sent":"379"}

指向productpage的inbound条目
{"upstream_cluster":"inbound|9080|http|productpage.default.svc.cluster.local","downstream_remote_address":"10.32.0.1:40938","authority":"10.109.209.72:9080","path":"/productpage","protocol":"HTTP/1.1","upstream_service_time":"1839","upstream_local_address":"127.0.0.1:51264","duration":"1840","upstream_transport_failure_reason":"-","route_name":"default","downstream_local_address":"10.40.0.12:9080","user_agent":"curl/7.47.0","response_code":"200","response_flags":"-","start_time":"2020-05-15T06:30:26.446Z","method":"GET","request_id":"e2de9f03-38ac-924d-ae2b-176d868c56ab","upstream_host":"127.0.0.1:9080","x_forwarded_for":"-","requested_server_name":"-","bytes_received":"0","istio_policy_status":"-","bytes_sent":"5183"}

使用JSON Handler查看详细日志尤其是五元组信息和Flag
"outbound|9080||details.default.svc.cluster.local"

"outbound|9080||reviews.default.svc.cluster.local"

"inbound|9080|http|productpage.default.svc.cluster.local"

安装仪表板：
kubectl apply -f samples/addons

开放监控工具的NotePort端口
kubectl patch svc -n istio-system prometheus -p '{"spec":{"type": "NodePort"}}'
kubectl patch service prometheus --namespace=istio-system --type='json' --patch='[{"op": "replace", "path": "/spec/ports/0/nodePort", "value":31120}]'

kubectl patch svc -n istio-system grafana  -p '{"spec":{"type": "NodePort"}}'
kubectl patch service grafana --namespace=istio-system --type='json' --patch='[{"op": "replace", "path": "/spec/ports/0/nodePort", "value":31121}]'

kubectl patch svc -n istio-system tracing -p '{"spec":{"type": "NodePort"}}'
kubectl patch service tracing --namespace=istio-system --type='json' --patch='[{"op": "replace", "path": "/spec/ports/0/nodePort", "value":31122}]'

kubectl patch svc -n istio-system kiali -p '{"spec":{"type": "NodePort"}}'
kubectl patch service kiali --namespace=istio-system --type='json' --patch='[{"op": "replace", "path": "/spec/ports/0/nodePort", "value":31123}]'

压测脚本
while true; do curl http://node3:30329/productpage; done  

仪表板组件打开方式
prometheus: http://node1:31120/

grafana: http://node1:31121/

tracing: http://node1:31122/

kiali: http://node1:31123/

操作过程可参见
https://zhuanlan.zhihu.com/p/141775176 

清理整个环境

清理 Bookinfo
samples/bookinfo/platform/kube/cleanup.sh

卸载istio
kubectl delete -f samples/addons
istioctl manifest generate --set profile=demo | kubectl delete --ignore-not-found=true -f -
    Istio 卸载程序按照层次结构逐级的从 istio-system 命令空间中删除 RBAC 权限和所有资源。对于不存在的资源报错，可以安全的忽略掉，毕竟他们已经被分层的删除了。

删除命名空间 istio-system 
kubectl delete namespace istio-system

指示 Istio 自动注入 Envoy 边车代理的标签默认也不删除。 不需要的时候，使用下面命令删掉它。
kubectl label namespace default istio-injection-