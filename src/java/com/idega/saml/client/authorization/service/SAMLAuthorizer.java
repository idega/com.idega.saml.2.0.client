package com.idega.saml.client.authorization.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.idega.block.sso.model.AuthorizationSettings;

public interface SAMLAuthorizer {

	public void doSendAuthorizationRequest(AuthorizationSettings settings, HttpServletRequest request, HttpServletResponse response, String type) throws Exception;

	public String getRedirectURLAfterProcessedResponse(HttpServletRequest request, HttpServletResponse response, String type);

	public String getLogoutRequestURL(AuthorizationSettings settings, HttpServletRequest request, HttpServletResponse response) throws Exception;

	public boolean isDebug();

}