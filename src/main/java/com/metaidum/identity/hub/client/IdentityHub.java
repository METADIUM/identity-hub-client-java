package com.metaidum.identity.hub.client;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.metadium.vc.Verifiable;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.metaidum.did.resolver.client.document.PublicKey;
import com.metaidum.identity.hub.client.crypto.AES;
import com.metaidum.identity.hub.client.crypto.ECIES;
import com.metaidum.identity.hub.client.exception.CommitObjectException;
import com.metaidum.identity.hub.client.exception.HubCommunicationException;
import com.metaidum.identity.hub.client.request.BasicRequest;
import com.metaidum.identity.hub.client.request.BasicRequest.Interface;
import com.metaidum.identity.hub.client.request.CommitQueryRequest;
import com.metaidum.identity.hub.client.request.DeleteRequest;
import com.metaidum.identity.hub.client.request.ObjectCommitQueryRequest;
import com.metaidum.identity.hub.client.request.ObjectQueryRequest;
import com.metaidum.identity.hub.client.request.WriteRequest;
import com.metaidum.identity.hub.client.request.object.Auth;
import com.metaidum.identity.hub.client.request.object.CommitObject;
import com.metaidum.identity.hub.client.request.object.CommitObject.Operation;
import com.metaidum.identity.hub.client.request.object.EncryptedObjectPayload;
import com.metaidum.identity.hub.client.request.object.PermissionGrantPayload;
import com.metaidum.identity.hub.client.response.CommitQueryResponse;
import com.metaidum.identity.hub.client.response.HubResponseBase;
import com.metaidum.identity.hub.client.response.ObjectQueryResponse;
import com.metaidum.identity.hub.client.response.WriteObjectResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Identity Hub client
 * @author mansud
 *
 */
public class IdentityHub {
	// hub end point
	private static final String MAINNET_HUB_URL = "https://datahub.metadium.com/";
	private static final String TESTNET_HUB_URL = "https://testnetdatahub.metadium.com/";
	
	// default hub did
	private static final String MAINNET_HUB_DID_DEFAULT = "did:meta:0000000000000000000000000000000000000000000000000000000000000527";
	private static final String TESTNET_HUB_DID_DEFAULT = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004";
	
	/** Debug log */
	private static boolean bDebug = false;
	
	private static final String PERMISSION_GRANT_TYPE = "PermissionGrant";
	
	private static Logger logger = Logger.getLogger(IdentityHub.class.getName());
	
	private static String hubUrl = null;
	
	/**
	 * Set debug
	 * @param debug
	 */
	public static void setDebug(boolean debug) {
		bDebug = debug;
	}
	
	/**
	 * Set hub url
	 * @param url
	 */
	public static void setUrl(String url) {
		hubUrl = url;
	}
	
	/** OkHttpClient */
	private static OkHttpClient okHttpClient;
	
	/** ID of public key of identity hub **/
	private static String hubPublicKeyId;
	
	/** Public key of Identity hub */
	private static ECPublicKey hubPublicKey;
	
	/** is test net */
	private boolean bTestNet;

	/** hub did */
    private String hubDid;
    
    /** did of client */
    private String clientDid;
    
    /** key id of client */
    private String clientKeyId;
    
    /** signer of client */
    private JWSSigner clientSigner;
    
    private static synchronized OkHttpClient httpClient() {
        OkHttpClient.Builder httpClient = new OkHttpClient.Builder();
        return httpClient.build();
        
    }
    
    /**
     * Set public key of Identity hub
     * <p/>
     * 
     * @param keyID
     * @param ecPublicKey
     */
    public static void setPublicKeyOfIdentityHub(String keyID, ECPublicKey ecPublicKey) {
    	hubPublicKeyId = keyID;
    	hubPublicKey = ecPublicKey;
    }
    
    /**
     * Create IdentityHub client
     * @param isTestnet whether connect test net
     * @param did    of client
     * @param keyId  of client
     * @param signer of client
     */
    public IdentityHub(boolean isTestnet, String did, String keyId, JWSSigner signer) {
        if (okHttpClient == null) {
        	okHttpClient = httpClient();
        }
        hubDid = isTestnet ? TESTNET_HUB_DID_DEFAULT : MAINNET_HUB_DID_DEFAULT;
        bTestNet = isTestnet;
        clientDid = did;
        clientKeyId = keyId;
        clientSigner = signer;
    }
    
    /**
     * Create IdentityHub client to main net
     * @param did    of client
     * @param keyId  of client
     * @param signer of client
     */
    public IdentityHub(String did, String keyId, JWSSigner signer) {
    	this(false, did, keyId, signer);
    }
    
    /**
     * Request CommitQuery, ObjectQuery, WriteQuery ...
     * @param req Query request
     * @return response json string. if not verify, server fail, return null
     * @throws HubCommunicationException 
     * @throws IOException 
     */
    private String request(BasicRequest req) throws HubCommunicationException, IOException {
    	// for replay
    	Map<String, Object> customParams = new HashMap<>();
		customParams.put("did-request-nonce", UUID.randomUUID().toString());

		// sign request
    	JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.ES256K, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, clientKeyId, customParams, null);
    	JWSObject jws = new JWSObject(jwsHeader, new Payload(req.build().toString()));
    	try {
			jws.sign(clientSigner);
		}
    	catch (JOSEException e) {
    		throw new HubCommunicationException("Could not sign with given signer", e);
		}
    	
    	String requestBody = jws.serialize();
		
		Request request = new Request.Builder()
				.addHeader("content-type", "application/jwt")
				.url(hubUrl != null ? hubUrl : (bTestNet ? TESTNET_HUB_URL : MAINNET_HUB_URL))
				.post(RequestBody.create(null, requestBody))
				.build();
		
		long time = System.currentTimeMillis();
		if (bDebug) {
			logger.log(Level.INFO, "Hub-Request\nBody "+requestBody+"\nPayload "+jws.getPayload().toString());
		}
		
		// request
		Response response = okHttpClient.newCall(request).execute();
		if (response.isSuccessful()) {
			String serializedJws = response.body().string();
			
			// parse JWS
    		JWSObject jwsObject;
    		try {
    			jwsObject = JWSObject.parse(serializedJws);
    		}
    		catch (ParseException e) {
        		throw new HubCommunicationException("Response is not JWS", e);
    		}
    		
			if (bDebug) {
				logger.log(Level.INFO, "Hub-Response ("+(System.currentTimeMillis()-time)+"ms)\nBody "+serializedJws+"\nPayload "+jwsObject.getPayload().toString());
			}
    		
    		// Get document of did 
    		String resKid = jwsObject.getHeader().getKeyID();
    		
    		// Check if already setting public key id is same as public key of response
    		ECPublicKey ecPublicKey;
    		if (hubPublicKeyId != null && resKid.equals(hubPublicKeyId)) {
    			ecPublicKey = hubPublicKey;
    		}
    		else {
	    		String resDid = resKid.split("#")[0];
	    		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(resDid);
	    		if (didDocument == null) {
	    			// error
	    			throw new HubCommunicationException("Not register hub DID. "+resDid);
	    		}
	    		
	    		// Get public key
	    		PublicKey publicKeyObj = didDocument.getPublicKey(resKid);
	    		if (publicKeyObj == null) {
	    			throw new HubCommunicationException("Not exists key id in did document "+resKid);
	    		}
	    		
	    		ecPublicKey = (ECPublicKey)publicKeyObj.getPublicKey();
	    		if (ecPublicKey == null) {
	    			throw new HubCommunicationException("Not exists or invalid public key hex in did document "+resKid);
	    		}
    		}
    		
    		// verify response
    		try {
    			ECDSAVerifier verifier = new ECDSAVerifier(ecPublicKey);
    			verifier.getJCAContext().setProvider(new BouncyCastleProvider());
        		if (jwsObject.verify(verifier)) {
        			return jwsObject.getPayload().toString();
        		}
        		else {
        			throw new HubCommunicationException("Response validation failed");
        		}
    		}    			
    		catch (JOSEException e) {
    			throw new HubCommunicationException("Error verifying response", e);
    		}
    	}
		
    	throw new HubCommunicationException("Hub server error "+response.code());
    }
    
    /**
     * Request object query
     * @param subjectOwnerDid did of owner of object
     * @param inf             interface name to query
     * @param context         to query
     * @param types           of object. nullable
     * @param objectIds       id list of objects to find. nullable
     * @return object to find. If not found or error, return null
     * @throws JOSEException
     * @throws IOException
     * @throws ParseException
     */
    public ObjectQueryResponse objectQuery(String subjectOwnerDid, Interface inf, String context, List<String> types, List<String> objectIds) throws HubCommunicationException, IOException {
    	ObjectQueryRequest req = new ObjectQueryRequest();
    	req.setIssuer(clientDid);
    	req.setSubject(subjectOwnerDid);
    	req.setAudience(hubDid);
    	req.setQuery(inf, context, types, objectIds, null);

		return new Gson().fromJson(request(req), ObjectQueryResponse.class);
    }
    
    /**
     * Request commit query
     * @param subjectOwnerDid did of owner of object
     * @param objectId        to find
     * @param revision        to find. nullable
     * @param skipToken       nullable
     * @return commit contents
     * @throws JOSEException
     * @throws IOException
     * @throws ParseException
     */
    public CommitQueryResponse commitQuery(String subjectOwnerDid, String objectId, String revision, Object skipToken) throws HubCommunicationException, IOException {
    	CommitQueryRequest req = new CommitQueryRequest();
    	req.setIssuer(clientDid);
    	req.setSubject(subjectOwnerDid);
    	req.setAudience(hubDid);
    	req.setQuery(Collections.singletonList(objectId), revision, skipToken);
    	
    	return new Gson().fromJson(request(req), CommitQueryResponse.class) ;
    }
    
    /**
     * Request object commit query 
     * @param inf             interface name to query
     * @param context         to query
     * @param types           of object. nullable
     * @param objectIds       id list of objects to find. nullable
     * @return object to find. If not found or error, return null
     * @throws HubCommunicationException
     * @throws IOException
     */
    public CommitQueryResponse objectCommitQuery(String subjectOwnerDid, Interface inf, String context, List<String> types, List<String> objectIds) throws HubCommunicationException, IOException {
    	ObjectCommitQueryRequest req = new ObjectCommitQueryRequest();
    	req.setIssuer(clientDid);
    	req.setSubject(subjectOwnerDid);
    	req.setAudience(hubDid);
    	req.setQuery(inf, context, types, objectIds, null);

    	return new Gson().fromJson(request(req), CommitQueryResponse.class) ;
    }
    
    /**
     * Request write object
     * @param subjectOwnerDid did of owner of object
     * @param commit          to commit object
     * @return response
     * @throws JOSEException
     * @throws IOException
     * @throws ParseException
     */
    public WriteObjectResponse writeRequest(String subjectOwnerDid, CommitObject commit) throws HubCommunicationException, IOException {
    	WriteRequest req = new WriteRequest();
    	req.setIssuer(clientDid);
    	req.setSubject(subjectOwnerDid);
    	req.setAudience(hubDid);
	
    	try {
			commit.sign(clientSigner);
		}
    	catch (JOSEException e) {
    		new HubCommunicationException("Error when signing commit object", e);
		}
    	req.setCommit(commit);
    
    	return new Gson().fromJson(request(req), WriteObjectResponse.class) ;
    }
    
    /**
     * Request delete all object of subject
     * @param subjectOwnerDid owner did of subject
     * @return response
     * @throws JsonSyntaxException
     * @throws JOSEException
     * @throws IOException
     * @throws ParseException
     */
    public HubResponseBase deleteRequest(String subjectOwnerDid) throws HubCommunicationException, IOException {
    	DeleteRequest req = new DeleteRequest();
    	req.setIssuer(clientDid);
    	req.setSubject(subjectOwnerDid);
    	req.setAudience(hubDid);
    	return new Gson().fromJson(request(req), HubResponseBase.class);
    }
    
    /**
     * Request to get recent commits of objects
     * @param subjectOwnerDid did of onwer of object
     * @param types           type of object
     * @param privateKey      to decrypt contents
     * @return commit JWS object (not exists signature) to decrypted. header is commit header, payload is signed verifiable, if not found, return null
     * @throws HubCommunicationException
     * @throws IOException network error
     * @throws CommitObjectException 
     */
    public List<CommitObject> getDecryptedCommitsOfObjects(String subjectOwnerDid, List<String> types, BCECPrivateKey privateKey) throws HubCommunicationException, IOException, CommitObjectException {
    	// request ObjectCommitQuery
    	CommitQueryResponse commitResponse = objectCommitQuery(subjectOwnerDid, Interface.Collections, Verifiable.JSONLD_CONTEXT_CREDENTIALS, types, null);
    	
    	List<CommitObject> ret = new ArrayList<>();
    	if (commitResponse != null) {
    		for (CommitQueryResponse.Commit commit : commitResponse.getCommits()) {
    			ret.add(decryptAndVerifyCommitQueryResponse(subjectOwnerDid, commit, privateKey));
    		}
    	}
    	
    	return ret;
    }
    
    private CommitObject decryptAndVerifyCommitQueryResponse(String subjectOwnerDid, CommitQueryResponse.Commit commit, BCECPrivateKey privateKey) throws CommitObjectException {
    	// Verify commit content
    	JWSObject commitObject;
		try {
			commitObject = new JWSObject(new Base64URL(commit.getProtectedHeader()), new Base64URL(commit.getPayload()), new Base64URL(commit.getSignature()));
		}
		catch (ParseException e1) {
			throw new CommitObjectException("Commit is not JWS", e1);
		}
		
		if (bDebug) {
			logger.log(Level.INFO, "Hub-Response CommitedObject\nHeader "+commitObject.getHeader().toString()+"\nPayload "+commitObject.getPayload().toString());
		}
		
		// 요청자와 owner 가 같으면 검증 하지 않음
		String resKid = commitObject.getHeader().getKeyID();
		if (!clientDid.equals(subjectOwnerDid) || !resKid.equals(clientKeyId)) {
			verifyJws(commitObject);
		}
		
		// Verify encrypted content
		JWSObject encryptedJWT;
		try {
			encryptedJWT = JWSObject.parse(commitObject.getPayload().toString());
		} catch (ParseException e1) {
			throw new CommitObjectException("Error when verifying commit", e1);
		}
		if (bDebug) {
			logger.log(Level.INFO, "Hub-Response EncryptVerifiable\nHeader "+encryptedJWT.getHeader().toString());
		}
		
		resKid = encryptedJWT.getHeader().getKeyID();
		if (!clientDid.equals(subjectOwnerDid) || !resKid.equals(clientKeyId)) {
			verifyJws(encryptedJWT);
		}
		
		// get encrypted secret key
		Gson gson = new Gson();
		Auth auth = gson.fromJson(gson.toJson(encryptedJWT.getHeader().getCustomParam("auth")), Auth.class);
		String encryptedKey = null;
		if (clientDid.equals(subjectOwnerDid)) {
			// owner verifiable
			if (auth.getOwner() != null) {
				encryptedKey = auth.getOwner().getEncryptedKey();
			}
		}
		else {
			// grantee verifiable
			if (auth.getGrantee() != null) {
				for (Auth.Key k : auth.getGrantee()) {
					if (clientKeyId.equals(k.getId())) {
						encryptedKey = k.getEncryptedKey();
						break;
					}
				}
			}
		}
		if (encryptedKey == null) {
			throw new CommitObjectException("not found to match kid");
		}

		// decrypt secret key
		byte[] secretKey;
		try {
			secretKey = ECIES.decrypt(privateKey, new Base64URL(encryptedKey).decode());
		} catch (GeneralSecurityException e1) {
			throw new CommitObjectException("Error when decrypt encrypted secret key", e1);
		}
		byte[] iv = new Base64URL(auth.getInitialVector()).decode();
		byte[] decryptedPayload;
		try {
		
			decryptedPayload = AES.decryptWithCbcPKCS7Padding(secretKey, iv, encryptedJWT.getPayload().toBytes());
		}
		catch (Exception e) {
			throw new CommitObjectException("Error when decrypt encrypt verifiable", e);
		}
		
		// Convert to verifiable
		String verifiableJsonString = new String(decryptedPayload, StandardCharsets.UTF_8);
		SignedJWT verifiableJwts;
		try {
			verifiableJwts = SignedJWT.parse(verifiableJsonString);
		}
		catch (ParseException e) {
			throw new CommitObjectException("verifiable is not signed JWT", e);
		}
		if (bDebug) {
			logger.log(Level.INFO, "Hub-Response Verifiable\nHeader "+verifiableJwts.getHeader().toString()+"\nPayload "+verifiableJwts.getPayload().toString());
		}

		String verifierKeyId = verifiableJwts.getHeader().getKeyID();
		if (verifierKeyId == null) {
			throw new CommitObjectException("not found kid in verifiable");
		}
		
		// Verify verifiable
		if (!clientDid.equals(subjectOwnerDid)) {
			verifyJws(verifiableJwts);
		}
		

		// protected + header
		JWSHeader.Builder headerBuilder = new JWSHeader.Builder(commitObject.getHeader());
		headerBuilder.customParams(new HashMap<>(commitObject.getHeader().getCustomParams()));
		for (String key : commit.getHeader().keySet()) {
			headerBuilder.customParam(key, commit.getHeader().get(key));
		}
			
		return new CommitObject(headerBuilder.build(), new Payload(verifiableJsonString));
    }
    

    /**
     * Encrypt verifiable
     * @param publickey   of requester
     * @param verifiable  to encrypt
     * @param granteeDids did list of grantee
     * @return
     */
    private EncryptedObjectPayload encryptVerifiable(BCECPublicKey publickey, SignedJWT verifiable, List<String> granteeDids) {
    	// Get public key of grantee
    	List<PublicKey> granteePublicKeys = new ArrayList<>();
    	if (granteeDids != null) {
	    	for (String granteeDid : granteeDids) {
	    		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(granteeDid);
	    		if (didDocument == null) {
	    			throw new NullPointerException("did not found");
	    		}
	    		PublicKey tmp = null;
	    		for (PublicKey publicKey : didDocument.getPublicKey()) {
	    			if (publicKey.getPublicKeyHex() != null) {
	    				tmp = publicKey;
	    			}
	    		}
	    		if (tmp != null) {
	    			granteePublicKeys.add(tmp);
	    		}
	    		else {
	    			throw new NullPointerException("did not publickey hex. "+didDocument.getId());
	    		}
	    	}
    	}
		
    	// generate IV
    	SecureRandom rnd = new SecureRandom();
    	byte[] iv = new byte[16];
    	rnd.nextBytes(iv);

    	EncryptedObjectPayload.Builder builder = new EncryptedObjectPayload.Builder()
    			.setKeyId(clientKeyId);
    	
    	Auth auth = new Auth();
    	auth.setEncryptAlgorithm("ECIES-AES256");
    	auth.setInitialVector(Base64URL.encode(iv).toString());

    	try {
    		// generate secret
    		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    		keyGen.init(256);
    		SecretKey secretKey = keyGen.generateKey();
    		
    		// encrypt verifiable with AES
    		byte[] encryptedData = AES.encrptyWithCbcPKCS7Padding(secretKey.getEncoded(), iv, verifiable.serialize().getBytes(Charset.forName("utf-8")));
    		builder.setEncryptedData(Base64URL.encode(encryptedData));
    		
    		// encrypt secret key with public key of self
    		auth.setOwner(new Auth.Key(clientKeyId, Base64URL.encode(ECIES.encrypt(publickey, secretKey.getEncoded())).toString()));
    		
    		// encrypt secret key with public key of grantees
    		List<Auth.Key> grantee = new ArrayList<>();
    		for (PublicKey granteePublicKey : granteePublicKeys) {
    			BCECPublicKey publicKey = (BCECPublicKey)granteePublicKey.getPublicKey();
    			grantee.add(new Auth.Key(granteePublicKey.getId(), Base64URL.encode(ECIES.encrypt(publicKey, secretKey.getEncoded())).toString()));
    		}
    		auth.setGrantee(grantee);
    	}
    	catch (Exception e) {
    		throw new SecurityException("encrypt error", e);
    	}
    	
    	builder.setAuth(auth);
    	
    	return builder.build();
    }
    
    /**
     * Get types of verifiable
     * @param verifiable to get type
     * @return types list
     * @throws ParseException
     * @throws CommitObjectException 
     */
    @SuppressWarnings("unchecked")
	private List<String> getTypeInVerifiable(SignedJWT verifiable) throws CommitObjectException {
    	List<String> types;
    	JWTClaimsSet vcp;
		try {
			vcp = verifiable.getJWTClaimsSet();
		}
		catch (ParseException e) {
			throw new CommitObjectException("invalid verifiable");
		}
    	if (vcp.getClaim("vc") != null) {
    		types = (List<String>)((Map<String, Object>)vcp.getClaim("vc")).get("type");
    	}
    	else if (vcp.getClaim("vp") != null) {
    		types = (List<String>)((Map<String, Object>)vcp.getClaim("vp")).get("type");
    	}
    	else {
    		throw new CommitObjectException("not found 'type' in verifiable");
    	}
    	
    	return types;
    }
    
    /**
     * Request write verifiable
     * @param subjectOwnerDid  owner did of subject
     * @param publickey        key to encryt verifiable
     * @param verifiable       to write
     * @param operation        create or update. If is update, must provide objectId 
     * @param objectId         if operation is update, replace, must not null
     * @param granteeDids      grantee did list
     * @return response
     * @throws HubCommunicationException 
     * @throws IOException
     * @throws CommitObjectException 
     */
    public WriteObjectResponse writeRequestForVerifiableObject(String subjectOwnerDid, BCECPublicKey publickey, SignedJWT verifiable, Operation operation, String objectId,  List<String> granteeDids) throws HubCommunicationException, IOException, CommitObjectException {
    	long time = System.currentTimeMillis();
    	EncryptedObjectPayload payload = encryptVerifiable(publickey, verifiable, granteeDids);
    	if (bDebug) {
    		logger.log(Level.INFO, "Encrypt commit verifiable "+(System.currentTimeMillis()-time)+"ms");
    	}
    	try {
			payload.sign(clientSigner);
		}
    	catch (JOSEException e) {
			throw new CommitObjectException("not found 'type'", e);
		}
    	
    	CommitObject.Builder builder = new CommitObject.Builder()
    	    	.setInterface(Interface.Collections)
    	    	.setContext("https://w3id.org/credentials/v1")
    	    	.setTypes(getTypeInVerifiable(verifiable))
    	    	.setOperation(operation)
    	    	.setCommittedAt(new Date())
    	    	.setCommitStrategy("basic")
    	    	.setSubject(subjectOwnerDid)
    	    	.setIssuer(clientDid)
    	    	.setKeyId(clientKeyId)
    	    	.setPayload(new Payload(payload.serialize()));
    	
    	if (operation == Operation.update || operation == Operation.replace) {
    		if (objectId != null) {
    			builder.setObjectId(objectId);
    		}
    		else {
    			throw new IllegalArgumentException("If operation is update, must provide object id");
    		}
    	}
    	
    	return writeRequest(subjectOwnerDid, builder.build());
    }
    
    /**
     * Write verifiable. if already exists object, update
     * @param subjectOwnerDid owner did of subject
     * @param publickey       public key to encrypt
     * @param verifiable      contents
     * @param granteeDids     did list of grantee
     * @return write response
     * @throws JOSEException
     * @throws IOException
     * @throws ParseException
     * @throws HubCommunicationException 
     * @throws CommitObjectException 
     */
    public WriteObjectResponse writeRequestForVerifiableObjectIfNeedUpdate(String subjectOwnerDid, BCECPublicKey publickey, SignedJWT verifiable, List<String> granteeDids) throws HubCommunicationException, IOException, CommitObjectException {
    	List<String> types = getTypeInVerifiable(verifiable);

		ObjectQueryResponse objectQueryResponse = objectQuery(subjectOwnerDid, Interface.Collections, Verifiable.JSONLD_CONTEXT_CREDENTIALS, types, null);
    	if (objectQueryResponse == null || objectQueryResponse.getObjects().size() == 0) {
    		return writeRequestForVerifiableObject(subjectOwnerDid, publickey, verifiable, Operation.create, null, granteeDids);
    	}
    	
    	return writeRequestForVerifiableObject(subjectOwnerDid, publickey, verifiable, Operation.update, objectQueryResponse.getObjects().get(0).getId(), granteeDids);
    }
    

    /**
     * write request for delete object
     * @param subjectOwnerDid owner did of subject
     * @param inf                   interface. Collections or Permissions
     * @param context               context of object
     * @param types                 types of object
     * @param objectId              objectId
     * @return response
     * @throws IOException 
     * @throws HubCommunicationException 
     */
    public WriteObjectResponse writeRequestForDelete(String subjectOwnerDid, Interface inf, String context, List<String> types, String objectId) throws HubCommunicationException, IOException {
    	CommitObject.Builder builder = new CommitObject.Builder()
    	.setInterface(inf)
    	.setContext(context)
    	.setOperation(Operation.delete)
    	.setCommittedAt(new Date())
    	.setCommitStrategy("basic")
    	.setSubject(subjectOwnerDid)
    	.setIssuer(clientDid)
    	.setKeyId(clientKeyId)
    	.setObjectId(objectId)
    	.setPayload(new Payload(""));
    	
    	if (types.size() == 1) {
    		builder.setType(types.get(0));
    	}
    	else {
    		builder.setTypes(types);
    	}
    	
    	return writeRequest(subjectOwnerDid, builder.build());
    }
    
    /**
     * write request for verifiable delete
     * @param subjectOwnerDid owner did of subject
     * @param types           types
     * @param objectId        to delete
     * @return
     * @throws HubCommunicationException 
     * @throws IOException
     */
    public WriteObjectResponse writeRequestForVerifiableDelete(String subjectOwnerDid, List<String> types, String objectId) throws HubCommunicationException, IOException {
    	return writeRequestForDelete(subjectOwnerDid, Interface.Collections, Verifiable.JSONLD_CONTEXT_CREDENTIALS, types, objectId);
    }
    
    /**
     * write request for permission delete
     * @param subjectOwnerDid owner did of subject
     * @param objectId        to delete
     * @return
     * @throws IOException 
     * @throws HubCommunicationException 
     */
    public WriteObjectResponse writeRequestForPermissionDelete(String subjectOwnerDid, String objectId) throws HubCommunicationException, IOException {
    	return writeRequestForDelete(subjectOwnerDid, Interface.Permissions, BasicRequest.context, Collections.singletonList(PERMISSION_GRANT_TYPE), objectId);
    }
    
    /**
     * write permisson
     * @param subjectOwnerDid owner did of subject
     * @param objectId        permission object id for update
     * @param operation       create or update
     * @param payload         grant payload
     * @return response
     * @throws HubCommunicationException 
     * @throws IOException
     */
    public WriteObjectResponse writeRequestForPermission(String subjectOwnerDid, String objectId, Operation operation, PermissionGrantPayload payload) throws HubCommunicationException, IOException {
    	CommitObject.Builder builder = new CommitObject.Builder()
    			.setInterface(Interface.Permissions)
    			.setContext(BasicRequest.context)
    			.setType(PERMISSION_GRANT_TYPE)
    			.setOperation(operation)
    			.setCommittedAt(new Date())
    			.setCommitStrategy("basic")
    			.setSubject(subjectOwnerDid)
    			.setIssuer(clientDid)
    			.setKeyId(clientKeyId)
    			.setPayload(new Payload(payload.toString()));
    	
    	if (operation == Operation.update) {
    		if (objectId != null) {
    			builder.setObjectId(objectId);
    		}
    		else {
    			throw new HubCommunicationException("If operation is update, must provide object id");
    		}
    	}
    	
    	return writeRequest(subjectOwnerDid, builder.build());
    }



    private void verifyJws(JWSObject jwsObject) throws CommitObjectException {
    	String did = (String)jwsObject.getHeader().getCustomParam("iss");
		if (did == null) {
			did = jwsObject.getHeader().getKeyID().split("#")[0];
		}
    	
		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(did);
		PublicKey publicKey = didDocument.getPublicKey(jwsObject.getHeader().getKeyID());
		ECDSAVerifier verifier;
		try {
			verifier = new ECDSAVerifier((ECPublicKey)publicKey.getPublicKey());
			verifier.getJCAContext().setProvider(new BouncyCastleProvider());
		} catch (JOSEException e1) {
			throw new CommitObjectException("Invalid public key. "+publicKey.getPublicKeyHex(), e1);
		}
		try {
			if (!jwsObject.verify(verifier)) {
				throw new CommitObjectException("Verify failed");
			}
		} catch (JOSEException e1) {
			throw new CommitObjectException("Error when verifying", e1);
		}
    }


}
