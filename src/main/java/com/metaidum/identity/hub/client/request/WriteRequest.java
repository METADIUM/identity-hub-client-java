package com.metaidum.identity.hub.client.request;

import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.JWSObject;


/**
 * Write request of identity hub<br/>
 * 
 * <pre>
 * {
 *   "@context": "https://schema.identity.foundation/0.1",
 *   "@type": "CommitQueryRequest",
 *   "iss": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000332",
 *   "aud": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004",
 *   "sub": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000332",
 *   "commit": {
 *     "protected":".....",
 *     "payload":"...",
 *     "signature":"..."
 *   }
 * }
 * </pre>
 * 
 * @author mansud
 *
 */
public class WriteRequest extends BasicRequest {
	@Override
	Type type() {
		return Type.WriteRequest;
	}
	
	/**
	 * set commit object. object is JWS to write
	 * @param jws object to write
	 */
	public void setCommit(JWSObject jws) {
		Map<String, Object> commit = new LinkedHashMap<String, Object>(); 
		commit.put("protected", jws.getHeader().toBase64URL().toString());
		commit.put("payload", jws.getPayload().toBase64URL().toString());
		commit.put("signature", jws.getSignature().toString());
		
		addClaim("commit", commit);
	}
}
