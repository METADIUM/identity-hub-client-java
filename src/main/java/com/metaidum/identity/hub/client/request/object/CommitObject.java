package com.metaidum.identity.hub.client.request.object;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.metadium.vc.util.DateUtils;
import com.metaidum.identity.hub.client.request.BasicRequest.Interface;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;

/**
 * object to commit for WriteRequest<br/>
 * <pre>
 * {
 *   "commit_strategy": "basic",
 *   "sub": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b",
 *   "committed_at": "2019-09-26T01:12:12Z",
 *   "kid": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511",
 *   "context": "https://w3id.org/credentials/v1",
 *   "iss": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b",
 *   "interface": "Collections",
 *   "type": [
 *     "VerifiablePresentation",
 *     "TestPresentation"
 *   ],
 *   "operation": "create",
 *   "alg": "ES256K"
 * }
 * </pre>
 * 
 * @author mansud
 *
 */
public class CommitObject extends JWSObject {
	private static final long serialVersionUID = 110052739491418400L;


	public enum Operation {
		create,
		update,
		delete,
		replace
	}
	
	public CommitObject(JWSHeader header, Payload payload) {
		super(header, payload);
	}
	
	public String getInterface() {
		return (String)getHeader().getCustomParam("interface");
	}
	
	public String getContext() {
		return (String)getHeader().getCustomParam("context");
	}
	
	@SuppressWarnings("unchecked")
	public List<String> getTypes() {
		Object type = getHeader().getCustomParam("type");
		if (type instanceof String) {
			return Collections.singletonList((String)type);
		}
		else if (type instanceof List) {
			return (List<String>)type;
		}
		return null;
	}
	
	public String getOperation() {
		return (String)getHeader().getCustomParam("operation");
	}
	
	public String getCommittedAt() {
		return (String)getHeader().getCustomParam("committed_at");
	}
	
	public String getCommitStrategy() {
		return (String)getHeader().getCustomParam("commit_strategy");
	}
	
	public String getSubject() {
		return (String)getHeader().getCustomParam("sub");
	}
	
	public String getIssuer() {
		return (String)getHeader().getCustomParam("iss");
	}
	
	public String getObjectId() {
		return (String)getHeader().getCustomParam("object_id");
	}

	public static class Builder {
		private JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256K);
		private Payload payload;
		
		public Builder setInterface(Interface inf) {
			headerBuilder.customParam("interface", inf.toString());
			return this;
		}
		
		public Builder setContext(String context) {
			headerBuilder.customParam("context", context);
			return this;
		}
		
		public Builder setTypes(List<String> types) {
			headerBuilder.customParam("type", types);
			return this;
		}
		
		public Builder setType(String type) {
			headerBuilder.customParam("type", type);
			return this;
		}
		
		public Builder setOperation(Operation operation) {
			headerBuilder.customParam("operation", operation.toString());
			return this;
		}
		
		public Builder setCommittedAt(Date date) {
			headerBuilder.customParam("committed_at", DateUtils.toRFC3339UTC(date));
			return this;
		}
		
		public Builder setCommitStrategy(String strategy) {
			headerBuilder.customParam("commit_strategy", strategy);
			return this;
		}
		
		public Builder setSubject(String subject) {
			headerBuilder.customParam("sub", subject);
			return this;
		}
		
		public Builder setKeyId(String keyId) {
			headerBuilder.keyID(keyId);
			return this;
		}
		
		public Builder setIssuer(String issuer) {
			headerBuilder.customParam("iss", issuer);
			return this;
		}
		
		public Builder setObjectId(String objectId) {
			headerBuilder.customParam("object_id", objectId);
			return this;
		}
		
		public Builder setPayload(Payload payload) {
			this.payload = payload;
			return this;
		}
		
		public CommitObject build() {
			return new CommitObject(headerBuilder.build(), payload);
		}
	}

}
