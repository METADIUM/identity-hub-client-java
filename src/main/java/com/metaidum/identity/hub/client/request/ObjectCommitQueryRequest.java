package com.metaidum.identity.hub.client.request;

/**
 * ObjectCommitQuery request of Identity Hub
 * @author mansud
 *
 */
public class ObjectCommitQueryRequest extends ObjectQueryRequest {
	@Override
	Type type() {
		return Type.ObjectCommitQueryRequest;
	}
}
