package com.metaidum.identity.hub.client.response;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Base response of Query (Commit and Object)
 * 
 * @author mansud
 *
 */
public class QueryResponse extends HubResponseBase {
	@SerializedName("skip_token")
	@Expose
	private String skipToken;

	public String getSkipToken() {
		return skipToken;
	}

	public void setSkipToken(String skipToken) {
		this.skipToken = skipToken;
	}
}
