package com.metaidum.identity.hub.client.request;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CommitQuery request of identity hub
 * @author mansud
 *
 */
public class CommitQueryRequest extends BasicRequest {
	@Override
	Type type() {
		return Type.CommitQueryRequest;
	}

	/**
	 * Set query contents
     * {
     *   "@context": "https://schema.identity.foundation/0.1",
     *   "@type": "CommitQueryRequest",
     *   "query": {
     *     "object_id": [
     *       "9335e2daace4d41187f74ab7f2dda46993d3439ea1fe890009a953dcac1aa43d"
     *     ]
     *   },
     *   "iss": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000332",
     *   "aud": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004",
     *   "sub": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000332"
     * }
     * 
	 * @param objectId to commit query
	 * @param revision revision of object to commit query. optional null 
	 * @param skipToken skip token. optional null
	 */
	public void setQuery(List<String> objectIds, String revision, Object skipToken) {
		Map<String, Object> query = new LinkedHashMap<>();
		query.put("object_id", objectIds);
		if (revision != null) {
			query.put("revision", revision);
		}
		if (skipToken != null) {
			query.put("skip_token", skipToken);
		}
		addClaim("query", query);
	}
}
