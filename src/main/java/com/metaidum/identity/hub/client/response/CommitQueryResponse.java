package com.metaidum.identity.hub.client.response;

import java.util.List;
import java.util.Map;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Response of CommitQuery
 * 
 * @author mansud
 *
 */
public class CommitQueryResponse extends QueryResponse {
	@SerializedName("commits")
	@Expose
	private List<Commit> commits;
	
	
	public List<Commit> getCommits() {
		return commits;
	}

	public void setCommits(List<Commit> commits) {
		this.commits = commits;
	}


	public static class Commit {
		@SerializedName("protected")
		@Expose
		private String protectedHeader;
		
		@SerializedName("header")
		@Expose
		private Map<String, Object> header;
		
		@SerializedName("payload")
		@Expose
		private String payload;

		@SerializedName("signature")
		@Expose
		private String signature;

		public String getProtectedHeader() {
			return protectedHeader;
		}

		public void setProtectedHeader(String protectedHeader) {
			this.protectedHeader = protectedHeader;
		}

		public Map<String, Object> getHeader() {
			return header;
		}

		public void setHeader(Map<String, Object> header) {
			this.header = header;
		}

		public String getPayload() {
			return payload;
		}

		public void setPayload(String payload) {
			this.payload = payload;
		}

		public String getSignature() {
			return signature;
		}

		public void setSignature(String signature) {
			this.signature = signature;
		}
	}
}
