package com.metadium.identity.hub.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.net.URI;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.LinkedHashMap;
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
	
	private static final String did = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b";
	private static final String keyId = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511";
	private static final String privateKeyHex = "86975dca6a36062768cf4b648b5b3f712caa2d1d61fa42520624a8e574788822";
	private static final String publicKeyHex = "d3e33a1791e77362130f9c11352933ea035e6fa3079610aa60ba800c9b963e132ed8db542d305027c4f1738efbed15bc63dc9f619c74c8e68287576769f5da3e";
	private static final BCECPrivateKey privateKey = ECKeyUtils.toECPrivateKey(Numeric.toBigInt(privateKeyHex), "secp256k1");
	private static final BCECPublicKey publicKey = ECKeyUtils.toECPublicKey(Numeric.toBigInt(publicKeyHex), "secp256k1");
	private IdentityHub hubClient;
	
	private static final String spDid = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000592";
	private static final String spKeyId = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000592#MetaManagementKey#c3c222f5dff072cbdb0850f543ea7956a22f8ce1";
	private static final String spPrivateKeyHex = "1b3fbf21f3b9083a130433cbe6baa60673afafe8ee1e4d2f84f37e634b2b0016";
	private static final String spPublicKeyHex = "04bd971508d033a52c570522572bee410a307ebd8858218cf34ef45dd365dd111a77eb39180d09fde10cd05dbf1d34d98a3c39f798caf39855cf754ebbe726c3ed";
	private static final BCECPrivateKey spPrivateKey = ECKeyUtils.toECPrivateKey(Numeric.toBigInt(spPrivateKeyHex), "secp256k1");
	private IdentityHub spHubClient;
	
	
	
	@Before
	public void setup() throws Exception {
		System.setOut(System.out);
		System.setErr(System.err);
		
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
		WriteObjectResponse writeResponse = hubClient.writeRequestForVerifiableObject(did, publicKey, signedVp, Operation.create, null, null);
		assertNotNull(writeResponse.getRevisions());
		assertEquals(1, writeResponse.getRevisions().size());
		
		// object query test
		String objectId = writeResponse.getRevisions().get(0);
		ObjectQueryResponse objectQueryResponse = hubClient.objectQuery(did, Interface.Collections, new ArrayList<>(vp.getContexts()).get(0), new ArrayList<>(vp.getTypes()), null);
		assertNotNull(objectQueryResponse.getObjects());
		assertEquals(1, objectQueryResponse.getObjects().size());
		
		// get verifiable test
		CommitObject commitObject = hubClient.getVerifiableObject(did, new ArrayList<>(vp.getTypes()), privateKey);
		assertNotNull(commitObject);
		assertEquals(objectId, commitObject.getHeader().getCustomParam("object_id"));
		
		SignedJWT readSignedJWT = commitObject.getPayload().toSignedJWT();
		assertEquals(signedVp.serialize(), readSignedJWT.serialize());
		
		// remove vp
		WriteObjectResponse removeResponse = hubClient.writeRequestForVerifiableDelete(did, new ArrayList<>(vp.getTypes()), objectId);
		assertNotNull(removeResponse.getRevisions());
		assertEquals(1, removeResponse.getRevisions().size());
		
		// empty verifiable test
		commitObject = hubClient.getVerifiableObject(did, new ArrayList<>(vp.getTypes()), privateKey);
		assertNull(commitObject);
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
		
		CommitObject commitObject = spHubClient.getVerifiableObject(did, new ArrayList<>(vp.getTypes()), spPrivateKey);
		assertNotNull(commitObject);
		
		SignedJWT readSignedJWT = commitObject.getPayload().toSignedJWT();
		assertEquals(signedVp.serialize(), readSignedJWT.serialize());
		
		// remove permission
		WriteObjectResponse removePermissionRes = hubClient.writeRequestForPermissionDelete(did, writePermissionResponse.getRevisions().get(0));
		assertNotNull(removePermissionRes.getRevisions());
		assertEquals(1, removePermissionRes.getRevisions().size());
		
		// not allowed permission test
		objectQueryResponse = spHubClient.objectQuery(did, Interface.Collections, new ArrayList<>(vp.getContexts()).get(0), new ArrayList<>(vp.getTypes()), null);
		assertEquals("permissions_required", objectQueryResponse.getErrorCode());
	}
}
