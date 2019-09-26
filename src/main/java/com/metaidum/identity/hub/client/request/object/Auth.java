package com.metaidum.identity.hub.client.request.object;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * auth param in JOSE header of commit object.
 * 
 * @author mansud
 *
 */
public class Auth {
	@SerializedName("enc")
	@Expose
	private String encryptAlgorithm;
	
	@SerializedName("iv")
	@Expose
	private String initialVector;
	
	@SerializedName("owner")
	@Expose
	private Key owner;
	
	@SerializedName("grantee")
	@Expose
	private List<Key> grantee;
	
	
	public String getEncryptAlgorithm() {
		return encryptAlgorithm;
	}

	public void setEncryptAlgorithm(String encryptAlgorithm) {
		this.encryptAlgorithm = encryptAlgorithm;
	}

	public String getInitialVector() {
		return initialVector;
	}

	public void setInitialVector(String initialVector) {
		this.initialVector = initialVector;
	}

	public Key getOwner() {
		return owner;
	}

	public void setOwner(Key owner) {
		this.owner = owner;
	}

	public List<Key> getGrantee() {
		return grantee;
	}

	public void setGrantee(List<Key> grantee) {
		this.grantee = grantee;
	}

	public static class Key {
		@SerializedName("kid")
		@Expose
		private String id;
		
		@SerializedName("encrypted_key")
		@Expose
		private String encryptedKey;
		
		public Key(String id, String encryptedKey) {
			setId(id);
			setEncryptedKey(encryptedKey);
		}

		public String getId() {
			return id;
		}

		public void setId(String id) {
			this.id = id;
		}

		public String getEncryptedKey() {
			return encryptedKey;
		}

		public void setEncryptedKey(String encryptedKey) {
			this.encryptedKey = encryptedKey;
		}
	}
	
	
}
