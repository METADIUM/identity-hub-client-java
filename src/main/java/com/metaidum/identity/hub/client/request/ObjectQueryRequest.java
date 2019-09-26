package com.metaidum.identity.hub.client.request;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ObjectQuery request of Identity Hub
 * @author mansud
 *
 */
public class ObjectQueryRequest extends BasicRequest {
	@Override
	Type type() {
		return Type.ObjectQueryRequest;
	}
	
	/**
	 * set query contents<br/>
	 * <pre>
	 * {
	 *     "@context": "https://schema.identity.foundation/0.1",
	 *	   "@type": "CommitQueryRequest",
     *     "query": {
     *         "interface": "Collections",
     *         "context": "https://w3id.org/credentials/v1",
     *         "type": ["VerifiableCredential"],
     *         "object_id": [
     *             "e086c4d03f44e9721a4ccdbab92470a54a52f322f80e121a7f955469da4d7ff5"
     *         ]
     *      },
     *      "iss": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004",
     *      "aud": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004",
     *      "sub": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000332"
     * }
	 * </pre>
	 * @param inf       interface
	 * @param context   context. optional null
	 * @param type      type. Credential or Presentation name
	 * @param objectIds to query. option null
	 * @param skipToken skip token. option null
	 */
	public void setQuery(Interface inf, String context, Object type, List<String> objectIds, Object skipToken) {
		Map<String, Object> query = new LinkedHashMap<>();
		query.put("interface", inf.toString());
		if (context != null) {
			query.put("context", context);
		}
		if (type != null) {
			query.put("type", type);
		}
		if (objectIds != null) {
			query.put("object_id", objectIds);
		}
		if (skipToken != null) {
			query.put("skip_token", skipToken);
		}
		
		addClaim("query", query);
	}
}
