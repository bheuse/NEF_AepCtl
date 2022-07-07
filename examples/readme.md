# WSO2 API Manager

## Starting via docker compose

[Details about WSO2 API Manager docker image](https://hub.docker.com/r/wso2/wso2am)

Example of docker compose service for WSO2 API Manager:
```yaml
wso2am:
container_name: wso2am
hostname: wso2am
image: ${dependencies.openet.docker.registry}/wso2/wso2am:4.0.0
ports:
- 8280:8280
- 8243:8243
- 9443:9443
- 9021:9021
- 8021:8021
networks:
- test_net
```

## WSO2 WSO2 API Manager Rest API

[WSO2 Admin Portal v2](https://apim.docs.wso2.com/en/latest/reference/product-apis/admin-apis/admin-v2/admin-v2/)

[WSO2 Publisher v2](https://apim.docs.wso2.com/en/latest/reference/product-apis/publisher-apis/publisher-v2/publisher-v2/)

[WSO2 Developer Portal v2](https://apim.docs.wso2.com/en/latest/reference/product-apis/devportal-apis/devportal-v2/devportal-v2/)

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

## WSO2 AM Soap API to manage users and roles

[Details](https://docs.wso2.com/display/IS580/Managing+Users+and+Roles+with+APIs)

### Examples:
1. [Create a new user](examples/soap-api/1.adduser.sh) ([Content](examples/soap-api/adduser.xml))
