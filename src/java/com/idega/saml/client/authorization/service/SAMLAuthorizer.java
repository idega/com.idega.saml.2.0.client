package com.idega.saml.client.authorization.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.idega.saml.client.model.AuthorizationSettings;

public interface SAMLAuthorizer {

	public void doSendAuthorizationRequest(AuthorizationSettings settings, HttpServletRequest request, HttpServletResponse response, String type) throws Exception;

	public String getRedirectURLAfterProcessedResponse(HttpServletRequest request, HttpServletResponse response, String type);

}