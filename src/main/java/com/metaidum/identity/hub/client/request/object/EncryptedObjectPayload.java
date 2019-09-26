package com.metaidum.identity.hub.client.request.object;

import java.util.Map;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;

/**
 * encrypt object payload of commit for write request<br/>
 * 
 * <pre>
 * {
 *   "typ": "JWT",
 *   "auth": {
 *     "enc": "ECIES-AES256",
 *     "iv": "7-CXOTvziAwzXqw3XvmtZA",
 *     "owner": {
 *       "kid": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511",
 *       "encrypted_key": "AqI5jUI66TjCo4V95vs_uxyfL2qRPZeaghXYNnjk9EmZUyiZyqkoCIRWMZCuQhEC-lPsBpu1X2TUFuutO1gT9rlOx3Gn65LgfCT4pXPAEYIMVhbr_uHRUGS76zZp_pu8jnrgPT-3My7nZev_nkVPrxCZ_IlfusNkojZ3s8RY6Ajd"
 *     },
 *     "grantee": [
 *       {
 *         "kid": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000592#MetaManagementKey#c3c222f5dff072cbdb0850f543ea7956a22f8ce1",
 *         "encrypted_key": "ArBYYLGvfBJWlYtJZruBxLQ8Nq6JnZ534Pub2A8ycoy31BCi283tHVgHZx6moN785foFp8kDOt0o1MxCCfKVb6c-uqDf2NL-9q0psxomzXakNcvlOy1zJnxgp7SBr_ZlqukdRRX9X1uAWyi-vb5y3fDpk4GFLSAM_uiSNPFDWR97"
 *       }
 *     ]
 *   },
 *   "alg": "ES256K",
 *   "kid": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511"
 * }
 * </pre>
 * 
 * @author mansud
 *
 */
public class EncryptedObjectPayload extends JWSObject {
	private static final long serialVersionUID = 5901835363216379747L;

	EncryptedObjectPayload(JWSHeader header, Payload payload) {
		super(header, payload);
	}

	public static class Builder {
		private JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256K).type(JOSEObjectType.JWT);
		private Auth auth;
		private Payload payload;
		
		public Builder setKeyId(String kid) {
			headerBuilder.keyID(kid);
			return this;
		}
				
		public Builder setAuth(Auth auth) {
			this.auth = auth;
			return this;
		}
				
		public Builder setEncryptedData(Base64URL encryptedData) {
			this.payload = new Payload(encryptedData);
			return this;
		}
		
		public EncryptedObjectPayload build() {
			Gson gson = new Gson();
			headerBuilder.customParam("auth", gson.fromJson(gson.toJsonTree(auth), Map.class));
			return new EncryptedObjectPayload(headerBuilder.build(), payload);
		}
	}
}
