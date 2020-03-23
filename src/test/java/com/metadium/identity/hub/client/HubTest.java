package com.metadium.identity.hub.client;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Before;
import org.junit.Test;
import org.web3j.utils.Numeric;

import com.metadium.vc.VerifiableCredential;
import com.metadium.vc.VerifiablePresentation;
import com.metadium.vc.VerifiableSignedJWT;
import com.metadium.vc.util.ECKeyUtils;
import com.metaidum.identity.hub.client.IdentityHub;
import com.metaidum.identity.hub.client.crypto.AES;
import com.metaidum.identity.hub.client.request.BasicRequest;
import com.metaidum.identity.hub.client.request.BasicRequest.Interface;
import com.metaidum.identity.hub.client.request.object.CommitObject;
import com.metaidum.identity.hub.client.request.object.CommitObject.Operation;
import com.metaidum.identity.hub.client.request.object.PermissionGrantPayload;
import com.metaidum.identity.hub.client.response.ObjectQueryResponse;
import com.metaidum.identity.hub.client.response.WriteObjectResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.SignedJWT;

public class HubTest {
	static {
		IdentityHub.setDebug(true);
	}
	
	private static final String did = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000087a";
	private static final String keyId = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000087a#MetaManagementKey#d364fbce2b48d1b61b70d55464a00692c16c1953";
	private static final String privateKeyHex = "cbf5bda2fc9e22472e7ae6159d9045269a8c07ac103dbbb10f2c3a230f68841f";
	private static final String publicKeyHex = "e6e8bab06a42e37badab2226a5d899cf936694a8a3dbe4d9a3cd13c260f4979edf2737dc453f987f66800c79365982ee80ac0c255781e37b1e77f6522b62dfdf";
	private static final BCECPrivateKey privateKey = ECKeyUtils.toECPrivateKey(Numeric.toBigInt(privateKeyHex), "secp256k1");
	private static final BCECPublicKey publicKey = ECKeyUtils.toECPublicKey(Numeric.toBigInt(publicKeyHex), "secp256k1");
	private IdentityHub hubClient;
	
	private static final String spDid = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000592";
	private static final String spKeyId = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000592#MetaManagementKey#c3c222f5dff072cbdb0850f543ea7956a22f8ce1";
	private static final String spPrivateKeyHex = "1b3fbf21f3b9083a130433cbe6baa60673afafe8ee1e4d2f84f37e634b2b0016";
	private static final String spPublicKeyHex = "04bd971508d033a52c570522572bee410a307ebd8858218cf34ef45dd365dd111a77eb39180d09fde10cd05dbf1d34d98a3c39f798caf39855cf754ebbe726c3ed";
	private static final BCECPrivateKey spPrivateKey = ECKeyUtils.toECPrivateKey(Numeric.toBigInt(spPrivateKeyHex), "secp256k1");
	private IdentityHub spHubClient;
	
	private static final String identityHubPublicKeyId = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004#MetaManagementKey#961c20596e7ec441723fbb168461f4b51371d8aa";
	private static final ECPublicKey identityHubPublicKey = ECKeyUtils.toECPublicKey(Numeric.hexStringToByteArray("0468677ff9dcf2fcb23c3e8633b651fefe9d0da82c99f738642f0967abc6dd653710d8750b522c738ffde22983ab384017783b95bd7512e1b929843db3d28a8b2d"), "secp256k1");
	
	static {
		IdentityHub.setPublicKeyOfIdentityHub(identityHubPublicKeyId, identityHubPublicKey);
	}
	
	@Before
	public void setup() throws Exception {
		System.setOut(System.out);
		System.setErr(System.err);
		
//		IdentityHub.setUrl("https://testnetih.metadium.com/");
//		DIDResolverAPI.getInstance().setResolverUrl("http://13.125.251.87:3006/1.0/");
		
		if (hubClient == null) {
			hubClient = new IdentityHub(true, did, keyId, new ECDSASigner(privateKey));
		}
		
		if (spHubClient == null) {
			spHubClient = new IdentityHub(true, spDid, spKeyId, new ECDSASigner(spPrivateKey));
		}
		
		// all delete before test
		hubClient.deleteRequest(did);
	}
	
	/**
	 * make test vp
	 * @return
	 * @throws JOSEException
	 */
	private SignedJWT makeTestVP() throws Exception {
		Calendar issued = Calendar.getInstance();
		Calendar expire = Calendar.getInstance();
		expire.setTime(issued.getTime());
		expire.add(Calendar.DAY_OF_YEAR, 100);
		
		// make name vc
		VerifiableCredential nameVc = new VerifiableCredential();
		nameVc.setId(URI.create("http://aa.metadium.com/credential/343"));
		nameVc.setIssuer(URI.create(did));
		nameVc.addTypes(Collections.singletonList("NameCredential"));
		nameVc.setIssuanceDate(issued.getTime());
		nameVc.setExpirationDate(expire.getTime());
		LinkedHashMap<String, String> subject = new LinkedHashMap<>();
		subject.put("id", did);
		subject.put("name", "YoungBae Jeon");
		nameVc.setCredentialSubject(subject);
		SignedJWT signedNameVc = VerifiableSignedJWT.sign(nameVc, JWSAlgorithm.ES256K, keyId, UUID.randomUUID().toString(), new ECDSASigner(privateKey));

		// make birth vc
		VerifiableCredential birthVc = new VerifiableCredential();
		birthVc.setId(URI.create("http://aa.metadium.com/credential/343"));
		birthVc.setIssuer(URI.create(did));
		birthVc.addTypes(Collections.singletonList("BirthCredential"));
		birthVc.setIssuanceDate(issued.getTime());
		birthVc.setExpirationDate(expire.getTime());
		subject = new LinkedHashMap<>();
		subject.put("id", did);
		subject.put("birth", "1977.02.06");
		birthVc.setCredentialSubject(subject);
		SignedJWT signedBirthVc = VerifiableSignedJWT.sign(birthVc, JWSAlgorithm.ES256K, keyId, UUID.randomUUID().toString(), new ECDSASigner(privateKey));
		
		// make vp
		VerifiablePresentation vp = new VerifiablePresentation();
		vp.addVerifiableCredential(signedNameVc.serialize());
		vp.addVerifiableCredential(signedBirthVc.serialize());
		vp.setId(URI.create("http://aa.metadium.com/credential/343"));
		vp.setHolder(URI.create(did));
		vp.addTypes(Collections.singletonList("TestPresentation"));
		
		return VerifiableSignedJWT.sign(vp, JWSAlgorithm.ES256K, keyId, UUID.randomUUID().toString(), new ECDSASigner(privateKey));
	}
	
	@Test
	public void presentationTest() throws Exception {
		// create vp
		SignedJWT signedVp = makeTestVP();
		VerifiablePresentation vp = (VerifiablePresentation)VerifiableSignedJWT.toVerifiable(signedVp);
		
		// write vp
		WriteObjectResponse writeResponse = hubClient.writeRequestForVerifiableObject(did, publicKey, signedVp, Operation.create, null, Collections.singletonList(spDid));
		assertNotNull(writeResponse.getRevisions());
		assertEquals(1, writeResponse.getRevisions().size());
		
		// object query test
		String objectId = writeResponse.getRevisions().get(0);
		ObjectQueryResponse objectQueryResponse = hubClient.objectQuery(did, Interface.Collections, new ArrayList<>(vp.getContexts()).get(0), new ArrayList<>(vp.getTypes()), null);
		assertNotNull(objectQueryResponse.getObjects());
		assertEquals(1, objectQueryResponse.getObjects().size());
		
		// get verifiable test
		List<CommitObject> commitObjects = hubClient.getDecryptedCommitsOfObjects(did, new ArrayList<>(vp.getTypes()), privateKey);
		assertTrue(commitObjects.size() == 1);
		assertEquals(objectId, commitObjects.get(0).getHeader().getCustomParam("object_id"));
		
		SignedJWT readSignedJWT = commitObjects.get(0).getPayload().toSignedJWT();
		assertEquals(signedVp.serialize(), readSignedJWT.serialize());
		
		// add permission for sp
		PermissionGrantPayload permissionPayload = new PermissionGrantPayload();
		permissionPayload.setContext(BasicRequest.context);
		permissionPayload.setAllow("-R--");
		permissionPayload.setOwner(did);
		permissionPayload.setGrantee(spDid);
		permissionPayload.setType( new ArrayList<>(vp.getTypes()));
		WriteObjectResponse writePermissionResponse = hubClient.writeRequestForPermission(did, writeResponse.getRevisions().get(0), Operation.create, permissionPayload);
		assertNotNull(writePermissionResponse.getRevisions());
		assertEquals(1, writePermissionResponse.getRevisions().size());

		commitObjects = spHubClient.getDecryptedCommitsOfObjects(did, new ArrayList<>(vp.getTypes()), spPrivateKey);
		assertTrue(commitObjects.size() == 1);
		assertEquals(objectId, commitObjects.get(0).getHeader().getCustomParam("object_id"));
		readSignedJWT = commitObjects.get(0).getPayload().toSignedJWT();
		assertEquals(signedVp.serialize(), readSignedJWT.serialize());
		
		
		// replace vp
		signedVp = makeTestVP();
		vp = (VerifiablePresentation)VerifiableSignedJWT.toVerifiable(signedVp);
		writeResponse = hubClient.writeRequestForVerifiableObject(did, publicKey, signedVp, Operation.replace, objectId, null);
		assertNotNull(writeResponse.getRevisions());
		assertEquals(1, writeResponse.getRevisions().size());

		// test to replaced vp
		commitObjects = hubClient.getDecryptedCommitsOfObjects(did, new ArrayList<>(vp.getTypes()), privateKey);
		assertTrue(commitObjects.size() == 1);
		assertEquals(signedVp.serialize(), commitObjects.get(0).getPayload().toSignedJWT().serialize());

		// remove vp
		WriteObjectResponse removeResponse = hubClient.writeRequestForVerifiableDelete(did, new ArrayList<>(vp.getTypes()), objectId);
		assertNotNull(removeResponse.getRevisions());
		assertEquals(1, removeResponse.getRevisions().size());
		
		// empty verifiable test
		commitObjects = hubClient.getDecryptedCommitsOfObjects(did, new ArrayList<>(vp.getTypes()), privateKey);
		assertTrue(commitObjects.size() == 0);
	}
	
	@Test
	public void permissionTest() throws Exception {
		// create vp
		SignedJWT signedVp = makeTestVP();
		VerifiablePresentation vp = (VerifiablePresentation)VerifiableSignedJWT.toVerifiable(signedVp);
		
		// write vp
		WriteObjectResponse writeResponse = hubClient.writeRequestForVerifiableObject(did, publicKey, signedVp, Operation.create, null, Collections.singletonList(spDid));
		assertNotNull(writeResponse.getRevisions());
		assertEquals(1, writeResponse.getRevisions().size());
		
		// not allowed permission test
		ObjectQueryResponse objectQueryResponse = spHubClient.objectQuery(did, Interface.Collections, new ArrayList<>(vp.getContexts()).get(0), new ArrayList<>(vp.getTypes()), null);
		assertEquals("permissions_required", objectQueryResponse.getErrorCode());

		// add permission for sp
		PermissionGrantPayload permissionPayload = new PermissionGrantPayload();
		permissionPayload.setContext(BasicRequest.context);
		permissionPayload.setAllow("-R--");
		permissionPayload.setOwner(did);
		permissionPayload.setGrantee(spDid);
		permissionPayload.setType( new ArrayList<>(vp.getTypes()));
		WriteObjectResponse writePermissionResponse = hubClient.writeRequestForPermission(did, writeResponse.getRevisions().get(0), Operation.create, permissionPayload);
		assertNotNull(writePermissionResponse.getRevisions());
		assertEquals(1, writePermissionResponse.getRevisions().size());
		
		// allowed permission test
		objectQueryResponse = spHubClient.objectQuery(did, Interface.Collections, new ArrayList<>(vp.getContexts()).get(0), new ArrayList<>(vp.getTypes()), null);
		assertNotNull(objectQueryResponse.getObjects());
		assertEquals(1, objectQueryResponse.getObjects().size());
		
		List<CommitObject> commitObjects = spHubClient.getDecryptedCommitsOfObjects(did, new ArrayList<>(vp.getTypes()), spPrivateKey);
		assertNotNull(commitObjects.size() > 0);
		
		SignedJWT readSignedJWT = commitObjects.get(0).getPayload().toSignedJWT();
		assertEquals(signedVp.serialize(), readSignedJWT.serialize());
		
		// remove permission
		WriteObjectResponse removePermissionRes = hubClient.writeRequestForPermissionDelete(did, writePermissionResponse.getRevisions().get(0));
		assertNotNull(removePermissionRes.getRevisions());
		assertEquals(1, removePermissionRes.getRevisions().size());
		
		// not allowed permission test
		objectQueryResponse = spHubClient.objectQuery(did, Interface.Collections, new ArrayList<>(vp.getContexts()).get(0), new ArrayList<>(vp.getTypes()), null);
		assertEquals("permissions_required", objectQueryResponse.getErrorCode());
	}
	
	@Test
	public void writePerformenceTest() throws Exception {
		Calendar issued = Calendar.getInstance();
		Calendar expire = Calendar.getInstance();
		expire.setTime(issued.getTime());
		expire.add(Calendar.DAY_OF_YEAR, 100);

		// prepared vc list
		List<SignedJWT> vcList = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			VerifiableCredential birthVc = new VerifiableCredential();
			birthVc.setId(URI.create("http://aa.metadium.com/credential/343"));
			birthVc.setIssuer(URI.create(did));
			birthVc.addTypes(Collections.singletonList("Birth"+i+"Credential"));
			birthVc.setIssuanceDate(issued.getTime());
			birthVc.setExpirationDate(expire.getTime());
			LinkedHashMap<String, String> subject = new LinkedHashMap<>();
			subject.put("id", did);
			subject.put("birth", "1977.02.06");
			birthVc.setCredentialSubject(subject);
			vcList.add(VerifiableSignedJWT.sign(birthVc, JWSAlgorithm.ES256K, keyId, UUID.randomUUID().toString(), new ECDSASigner(privateKey)));
		}
		
		long time = System.currentTimeMillis();
		for (SignedJWT vc : vcList) {
			long writeTime = System.currentTimeMillis();
			WriteObjectResponse writeResponse = hubClient.writeRequestForVerifiableObject(did, publicKey, vc, Operation.create, null, null /**Collections.singletonList(spDid)*/);
			assertTrue(writeResponse.getErrorCode() == null);
			System.out.println("Write VC time : "+(System.currentTimeMillis()-writeTime));
		}
		System.out.println("total write VC time = "+(System.currentTimeMillis()-time));
		
		// create vp
		VerifiablePresentation vp = new VerifiablePresentation();
		for (SignedJWT vc : vcList) {
			vp.addVerifiableCredential(vc.serialize());
		}
		vp.setId(URI.create("http://aa.metadium.com/credential/343"));
		vp.setHolder(URI.create(did));
		vp.addTypes(Collections.singletonList("MyPresentation"));
		SignedJWT signedVp = VerifiableSignedJWT.sign(vp, JWSAlgorithm.ES256K, keyId, UUID.randomUUID().toString(), new ECDSASigner(privateKey));
		
		// write vp
		time = System.currentTimeMillis();
		WriteObjectResponse writeResponse = hubClient.writeRequestForVerifiableObject(did, publicKey, signedVp, Operation.create, null, Collections.singletonList(spDid));
		assertTrue(writeResponse.getErrorCode() == null);
		System.out.println("Write VP time = "+(System.currentTimeMillis()-time));
	}
	
	@Test
	public void eciesTest() throws GeneralSecurityException {
		
		SecureRandom random = new SecureRandom();
		byte[] key = new byte[32];
		byte[] iv  = new byte[16];
		
		
		for (int i = 0; i < 1000; i++) {
			random.nextBytes(key);
			random.nextBytes(iv);
			
			byte[] message = new byte[Math.abs(random.nextInt())%1000];
			byte[] cipherText = AES.encrptyWithCbcPKCS7Padding(key, iv, message);
			byte[] decryptedText = AES.decryptWithCbcPKCS7Padding(key, iv, cipherText);
			
			assertArrayEquals(message, decryptedText);
		}
	}
	
	@Test
	public void getVPTest() throws Exception {
		List<CommitObject> vpList = hubClient.getDecryptedCommitsOfObjects(did, Arrays.asList(VerifiablePresentation.JSONLD_TYPE_PRESENTATION, "AA", "coinplug", "email"), privateKey);
	}
}
