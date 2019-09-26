package com.metaidum.identity.hub.client.exception;

/**
 * Exception when communicating with hub<br/>
 * Server error, request/response invalid format, did error ...
 * 
 * @author mansud
 *
 */
public class HubCommunicationException extends Exception {
	private static final long serialVersionUID = -2174143571853885808L;
	
	public HubCommunicationException(String message) {
		super(message);
	}

	public HubCommunicationException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}
}
