package com.metaidum.identity.hub.client.response;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Base response of hub
 * 
 * @author mansud
 *
 */
public class HubResponseBase {
	@SerializedName("@context")
	@Expose
	private String context;
	
	@SerializedName("@type")
	@Expose
	private String type;
	
	@SerializedName("developerMessage")
	@Expose
	private String developerMessage;
	
	@SerializedName("error_code")
	@Expose
	private String errorCode;
	
	@SerializedName("error_url")
	@Expose
	private String errorUrl;
	
	@SerializedName("inner_error")
	@Expose
	private InnerError innerError;
	
	@SerializedName("target")
	@Expose
	private String target;
	
	
	public String getContext() {
		return context;
	}

	public void setContext(String context) {
		this.context = context;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getDeveloperMessage() {
		return developerMessage;
	}

	public void setDeveloperMessage(String developerMessage) {
		this.developerMessage = developerMessage;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public String getErrorUrl() {
		return errorUrl;
	}

	public void setErrorUrl(String errorUrl) {
		this.errorUrl = errorUrl;
	}

	public InnerError getInnerError() {
		return innerError;
	}

	public void setInnerError(InnerError innerError) {
		this.innerError = innerError;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}
	
	public static class InnerError {
		@SerializedName("timestamp")
		@Expose
		private String timestamp;

		@SerializedName("stacktrace")
		@Expose
		private String stacktrace;

		public String getTimestamp() {
			return timestamp;
		}

		public void setTimestamp(String timestamp) {
			this.timestamp = timestamp;
		}

		public String getStacktrace() {
			return stacktrace;
		}

		public void setStacktrace(String stacktrace) {
			this.stacktrace = stacktrace;
		}
	}
}
