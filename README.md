# identity-hub-client-java

## Get it
### Maven
Add the JitPack repository to build file

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

Add dependency

```xml
<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>identity-hub-client-java</artifactId>
    <version>0.1.3</version>
</dependency>
```
### Gradle
Add root build.gradle

```gradle
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```
Add dependency

```gradle
dependencies {
    implementation 'com.github.METADIUM:identity-hub-client-java:0.1.3'
}
```


## Use it

### Register DID in Metadium



### Initialize hub client
```java
String did = "{did of client}";
String keyId = "{id of key to sign}";
BCECPrivateKey privateKey = ..;
ECDSASigner signer = new ECDSASigner(privateKey); // signer with client private key 
IdentityHub hubClient = new IdentityHub(true, did, keyId, signer);
```

### Get Verifiable Credential or Presentation of user from Identity-Hub
```java
String did = "{did of user}";


// Get verifiable credential
List<String> typesOfCrendential = Arrays.asList("VerifiableCredential", "NameCredential");
CommitObject commitObject = hubClient.verifiableQuery(did, typesOfCrendential, privateKey);
SignedJWT signedVc = commitObject.getPayload().toSignedJWT();
VerifiableCrendentail vc = (VerifiableCrendentail)VerifiableSignedJWT.toVerifiable(signedVc);


// Get verifiable presentation
List<String> typesOfPresentation = Arrays.asList("VerifiablePresentation", "ServicePresentation");
CommitObject commitObject = hubClient.verifiableQuery(did, typesOfPresentation, privateKey);
SignedJWT signedVp = commitObject.getPayload().toSignedJWT();
VerifiablePresentation vp = (VerifiablePresentation)VerifiableSignedJWT.toVerifiable(signedVp);

// Get verifiable credential of verifiable presentation
for (Object vc : verifiedVp.getVerifiableCredentials()) {
   SignedJWT signedVc = SignedJWT.parse((String)vc);
   VerifiableCredential vc = (VerifiableCredential)VerifiableSignedJWT.toVerifiable(signedVc);
}
```


