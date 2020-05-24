# spring-zuul-api-gateway
1) Authenticate request based on client_id, client_secret and Authorization Bearer Token - If client_id and Client_secret matches then it checks the token, if no token present in Bearer the generate new one, If present then check whether it is expired or not.
We have used public key for signing the JWT Token.
2) Route the request to API's based on API's service Id. Zuul by default uses ribbon from netflix which makes request to service instances on round-robin fashion e.g service1 - is having two instances one running on port 8081 and another on port 8082, so first request will go to service running on port 8081 then second request on port 8082 , third on 8081 again and so on.
It also passes down the header Authorization header along with token value to downstream apis. These downstream API authenticate the token using OAuth2 ResourceServer, using the key.

Applications to use in order to test this application
1)eureka-server
2)spring-zuul-api-gateway
3)spring-zuul-route-api1 - run this aplication on two ports,e.g 8082,8083
3)spring-zuul-route-api2 - run this aplication on two ports,e.g 8084,8085

url - http://localhost:8091/zuulapi1/route1, http://localhost:8091/zuulapi1/route4, http://localhost:8091/zuulapi2/route2, http://localhost:8091/zuulapi2/route3
client_id:clientid
client_secret:clientpassword
Authorization:Bearer

--- How to Create JKS file and public Key ------
1) Open Command Prompt in Administrative mode
2) Go to following directory and print the command
C:\Program Files\Java\jdk1.8.0_131\jre\bin>keytool -genkeypair -alias mytest -keyalg RSA -validity 1000 -keypass mypass -keystore mytest.jks -storepass mypass
3) You will see a file name mytest.jks will be created in bin folder
4)Now to get public Key run the command
C:\Program Files\Java\jdk1.8.0_131\jre\bin>keytool -list -rfc --keystore mytest.jks| openssl x509 -inform pem -pubkey
5) You will see public key printed on your console. Paste that into a text file.
