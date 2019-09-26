package com.metaidum.identity.hub.client.request;

/**
 * Delete request of identity hub<br/>
 * 
 * All object of subject delete
 * 
 * <pre>
 * {
 *     "@context": "https://schema.identity.foundation/0.1",
 *	   "@type": "DeleteRequest",
 *      "iss": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004",
 *      "aud": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000004",
 *      "sub": "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000332"
 * }
 * </pre>
 * 
 * @author mansud
 *
 */
public class DeleteRequest extends BasicRequest {

	@Override
	Type type() {
		return Type.DeleteRequest;
	}
}
