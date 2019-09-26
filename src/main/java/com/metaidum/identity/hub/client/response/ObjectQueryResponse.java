package com.metaidum.identity.hub.client.response;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Response of ObjectQuery
 * 
 * @author mansud
 *
 */
public class ObjectQueryResponse extends QueryResponse {
	@SerializedName("objects")
	@Expose
	private List<HubObject> objects;
	
	
	public List<HubObject> getObjects() {
		return objects;
	}

	public void setObjects(List<HubObject> objects) {
		this.objects = objects;
	}

	public static class HubObject {
		@SerializedName("interface")
		@Expose
		private String inf;
		
		@SerializedName("context")
		@Expose
		private String context;
		
		@SerializedName("type")
		@Expose
		private List<String> type;

		@SerializedName("id")
		@Expose
		private String id;
		
		@SerializedName("sub")
		@Expose
		private String subject;
		
		@SerializedName("created_at")
		@Expose
		private String createdAt;

		@SerializedName("created_by")
		@Expose
		private String createdBy;

		@SerializedName("commit_strategy")
		@Expose
		private String commitStrategy;

		public String getInterface() {
			return inf;
		}

		public void setInterface(String inf) {
			this.inf = inf;
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

		public String getId() {
			return id;
		}

		public void setId(String id) {
			this.id = id;
		}

		public String getSubject() {
			return subject;
		}

		public void setSubject(String subject) {
			this.subject = subject;
		}

		public String getCreatedAt() {
			return createdAt;
		}

		public void setCreatedAt(String createdAt) {
			this.createdAt = createdAt;
		}

		public String getCreatedBy() {
			return createdBy;
		}

		public void setCreatedBy(String createdBy) {
			this.createdBy = createdBy;
		}

		public String getCommitStrategy() {
			return commitStrategy;
		}

		public void setCommitStrategy(String commitStrategy) {
			this.commitStrategy = commitStrategy;
		}
	}
}
