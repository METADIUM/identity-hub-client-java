package com.metaidum.identity.hub.client.exception;

/**
 * Exception when validate object of commit
 * @author mansud
 *
 */
public class CommitObjectException extends Exception {
	private static final long serialVersionUID = 6643290723475214231L;

	public CommitObjectException(String message, Throwable cause) {
		super(message, cause);
	}

	public CommitObjectException(String message) {
		super(message);
	}

}
