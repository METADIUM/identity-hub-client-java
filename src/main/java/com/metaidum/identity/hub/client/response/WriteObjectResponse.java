package com.metaidum.identity.hub.client.response;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Response of WriteRequest
 * 
 * @author mansud
 *
 */
public class WriteObjectResponse extends HubResponseBase {
	@SerializedName("revisions")
	@Expose
	private List<String> revisions;

	public List<String> getRevisions() {
		return revisions;
	}

	public void setRevisions(List<String> revisions) {
		this.revisions = revisions;
	}
}
