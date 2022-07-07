
AF-DEMO Instrutions : NEF-330


# WSO2 API Manager Portals
- [API Manager Management Console](https://localhost:9443/carbon/)
- [API Manager Publisher Portal](https://localhost:9443/publisher)
- [API Manager Developer Portal](https://localhost:9443/devportal)

# WSO2 API Manager APIs
- [WSO2 Admin Portal Rest API](https://apim.docs.wso2.com/en/latest/reference/product-apis/admin-apis/admin-v2/admin-v2/)
- [WSO2 Publisher Rest API](https://apim.docs.wso2.com/en/latest/reference/product-apis/publisher-apis/publisher-v2/publisher-v2/)
- [WSO2 Developer Portal Rest API](https://apim.docs.wso2.com/en/latest/reference/product-apis/devportal-apis/devportal-v2/devportal-v2/)
- [WSO2 Users and Roles Soap API](https://docs.wso2.com/display/IS580/Managing+Users+and+Roles+with+APIs)

# WSO2 API Manager API Control Command Line
Download from [previous-releases](https://wso2.com/api-management/previous-releases/), select Tooling / CLI

```
$ ./apictl.exe add env production --apim https://localhost:9443
$ ./apictl.exe login production -u admin -p admin -k
```

### Examples:
1. [Obtain the consumer key/secret key pair](examples/rest-api/1.auth1.sh) ([Content](examples/rest-api/auth.json))
2. [Obtain the access token (use the above client id and secret)](examples/rest-api/2.auth2.sh)
3. [Create a Subscription level throttling policy](examples/rest-api/3.policy-create.sh) ([Content](examples/rest-api/policy-create.json))
4. [Create a new API](examples/rest-api/4.api-create.sh) ([Content](examples/rest-api/api-create.json))
5. [Update the swagger definition of the created API](examples/rest-api/5.api-update-def.sh)
6. [Create a new API revision](examples/rest-api/6.rev-create.sh) ([Content](examples/rest-api/rev-create.json))
7. [Deploy the created revision](examples/rest-api/7.deploy.sh) ([Content](examples/rest-api/deploy.json))
8. [Publish the created API](examples/rest-api/8.publish.sh)
9. [Create a new application](examples/rest-api/9.app-create.sh) ([Content](examples/rest-api/app-create.json))
10. [Create a new subscription providing for the created API and the created application](examples/rest-api/10.subscribe.sh) ([Content](examples/rest-api/subscribe.json))
11. [Generate keys (Consumer key/secret) for application](examples/rest-api/11.generate-app-keys.sh) ([Content](examples/rest-api/generate-app-keys.json))
12. [Send test request to created API and Application](examples/rest-api/12.test.sh)
13. [Create a new user Soap](examples/soap-api/1.adduser.sh) ([Content](examples/soap-api/adduser.xml))

### Steps to get access to WSO2 installation in AWS:

0. Login on Amdocs VPN 
1. Login on Openet VPN
2. Initially need to install kubectl if it’s not installed yet
3. To configure access to K8S need to put file eks-nef-cluster.yaml to ~/.kube directory with name ‘config’ without any extension.
4. Check connection to K8S and status of required pods by ‘kubectl get pods -n pentest | grep wso2’ command:
```
On Linux  : $ KUBE_CTL="kubectl"
On Cygwin : $ KUBE_CTL="/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/tools/kubectl.exe"

$ $KUBE_CTL get pods -n pentest | grep wso2
```
5. Forward port from K8S service to your local machine by 'kubectl port-forward service/wso2am-single-node-am-service 9443:9443 -n pentest &' command:
```
On Linux  : $ KUBE_CTL="kubectl"
On Cygwin : $ KUBE_CTL="/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/tools/kubectl.exe"

$ $KUBE_CTL get pods -n pentest | grep wso2
$ $KUBE_CTL port-forward service/wso2am-single-node-am-service 9443:9443 -n pentest &
$ $KUBE_CTL port-forward service/wso2am-single-node-am-service 8243:8243 -n pentest &
$ $KUBE_CTL port-forward service/nef-services-catalog-service 30106:8080 -n pentest  &
$ $KUBE_CTL port-forward service/nef-application-user-profile-service 30107:8080 -n pentest  &
```
6. Execute 1.auth1.sh, 2.auth2.sh and etc.
7. Gen Flask
```
$ java -jar tools/swagger-codegen-cli.jar generate -i NEF_Catalog_DataModel_API.yaml -l python-flask
```
