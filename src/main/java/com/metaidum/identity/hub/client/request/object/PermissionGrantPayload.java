package com.metaidum.identity.hub.client.request.object;

import java.util.List;

import com.google.gson.Gson;

/**
 * permission grant payload of commit for write request<br/>
 * 
 * <pre>
 * {
 *   "commit_strategy": "basic",
 *   "sub": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b",
 *   "committed_at": "2019-09-26T01:27:17Z",
 *   "kid": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511",
 *   "context": "https://schema.identity.foundation/0.1",
 *   "iss": "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b",
 *   "interface": "Permissions",
 *   "type": "PermissionGrant",
 *   "operation": "create",
 *   "alg": "ES256K"
 * }
 * </pre>
 * @author mansud
 *
 */
public class PermissionGrantPayload {
	private String owner;
	private String grantee;
	private String allow;
	private String context;
	private List<String> type;
	private String created_by;
	
	
	public String getOwner() {
		return owner;
	}
	
	public void setOwner(String owner) {
		this.owner = owner;
	}
	
	public String getGrantee() {
		return grantee;
	}
	
	public void setGrantee(String grantee) {
		this.grantee = grantee;
	}
	
	public String getAllow() {
		return allow;
	}
	
	public void setAllow(String allow) {
		this.allow = allow;
	}
	
	public String getContext() {
		return context;
	}
	
	public void setContext(String context) {
		this.context = context;
	}
	
	public List<String> getType() {
		return type;
	}
	
	public void setType(List<String> type) {
		this.type = type;
	}
	
	public String getCreated_by() {
		return created_by;
	}
	
	public void setCreated_by(String created_by) {
		this.created_by = created_by;
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}
}
