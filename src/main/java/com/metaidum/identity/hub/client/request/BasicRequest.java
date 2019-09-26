package com.metaidum.identity.hub.client.request;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * IdentityHub base request
 * @author mansud
 *
 */
public abstract class BasicRequest {
	public static final String context = "https://schema.identity.foundation/0.1";
	
	protected enum Type {
		WriteRequest,
		ObjectQueryRequest,
		CommitQueryRequest,
		DeleteRequest
	}
	
	public enum Interface {
		Collections,
		Permissions
	}

	private JWTClaimsSet.Builder jwtBuilder = new JWTClaimsSet.Builder();
	
	/**
	 * Request type
	 * @return
	 */
	abstract Type type();
	
	/**
	 * set issuer
	 * @param iss issuer did
	 */
	public void setIssuer(String iss) {
		jwtBuilder.issuer(iss);
	}

	/**
	 * set audience
	 * @param aud audience
	 */
	public void setAudience(String aud) {
		jwtBuilder.audience(aud);
	}
	
	public void setSubject(String sub) {
		jwtBuilder.subject(sub);
	}
	
	void addClaim(String name, Object value) {
		jwtBuilder.claim(name, value);
	}
	
	/**
	 * to JWT
	 * @return JWT
	 */
	public JWTClaimsSet build() {
		jwtBuilder.claim("@context", context);
		jwtBuilder.claim("@type", type().toString());
		return jwtBuilder.build();
	}
}
