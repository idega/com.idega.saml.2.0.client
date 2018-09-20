package com.idega.saml.client.authorization.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;

public class IdegaSamlAuth extends Auth {

	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(IdegaSamlAuth.class);

	/**
     * Settings data.
     */
	private Saml2Settings settings;

	/**
     * HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
     */
	private HttpServletRequest request;

	/**
     * HttpServletResponse object to be used (For example to execute the redirections).
     */
	private HttpServletResponse response;

	/**
     * NameID.
     */
	private String nameid;

	/**
     * NameIDFormat.
     */
	private String nameidFormat;

	/**
     * SessionIndex. When the user is logged, this stored it from the AuthnStatement of the SAML Response
     */
	private String sessionIndex;

	/**
     * SessionNotOnOrAfter. When the user is logged, this stored it from the AuthnStatement of the SAML Response
	 */
	private DateTime sessionExpiration;

	/**
	 * The ID of the last message processed
	 */
	private String lastMessageId;

	/**
	 * The ID of the last assertion processed
	 */
	private String lastAssertionId;

	/**
	 * The NotOnOrAfter values of the last assertion processed
	 */
	private List<Instant> lastAssertionNotOnOrAfter;

	/**
     * User attributes data.
     */
	private Map<String, List<String>> attributes = new HashMap<String, List<String>>();

	/**
     * If user is authenticated.
     */
	private boolean authenticated = false;

	/**
     * Stores any error.
     */
	private List<String> errors = new ArrayList<String>();

	/**
     * Reason of the last error.
     */
	private String errorReason;

	/**
	 * The id of the last request (Authn or Logout) generated
	 */
	private String lastRequestId;

	/**
	 * The most recently-constructed/processed XML SAML request
     * (AuthNRequest, LogoutRequest)
	 */
	private String lastRequest;

	/**
     * The most recently-constructed/processed XML SAML response
     * (SAMLResponse, LogoutResponse). If the SAMLResponse was
     * encrypted, by default tries to return the decrypted XML
	 */
	private String lastResponse;

	public IdegaSamlAuth(Saml2Settings settings, HttpServletRequest request, HttpServletResponse response) throws SettingsException {
		super(settings, request, response);

		this.settings = settings;
		this.request = request;
		this.response = response;
	}

	@Override
	public void processResponse(String requestId) throws Exception {
		authenticated = false;
		final HttpRequest httpRequest = ServletUtils.makeHttpRequest(this.request);
		final String samlResponseParameter = httpRequest.getParameter("SAMLResponse");

		if (samlResponseParameter != null) {
			SamlResponse samlResponse = new IdegaSamlResponse(settings, httpRequest);
			lastResponse = samlResponse.getSAMLResponseXml();

			if (samlResponse.isValid(requestId)) {
				nameid = samlResponse.getNameId();
				nameidFormat = samlResponse.getNameIdFormat();
				authenticated = true;
				attributes = samlResponse.getAttributes();
				sessionIndex = samlResponse.getSessionIndex();
				sessionExpiration = samlResponse.getSessionNotOnOrAfter();
				lastMessageId = samlResponse.getId();
				lastAssertionId = samlResponse.getAssertionId();
				lastAssertionNotOnOrAfter = samlResponse.getAssertionNotOnOrAfter();
				LOGGER.debug("processResponse success --> " + samlResponseParameter);
			} else {
				errors.add("invalid_response");
				LOGGER.error("processResponse error. invalid_response");
				LOGGER.debug(" --> " + samlResponseParameter);
				errorReason = samlResponse.getError();
			}
		} else {
			errors.add("invalid_binding");
			String errorMsg = "SAML Response not found, Only supported HTTP_POST Binding";
			LOGGER.error("processResponse error." + errorMsg);
			throw new Error(errorMsg, Error.SAML_RESPONSE_NOT_FOUND);
		}
	}

	@Override
	public final Saml2Settings getSettings() {
		return settings;
	}

	public final HttpServletRequest getRequest() {
		return request;
	}

	public final HttpServletResponse getResponse() {
		return response;
	}

	public final String getNameid() {
		return nameid;
	}

	public final String getNameidFormat() {
		return nameidFormat;
	}

	@Override
	public final String getLastMessageId() {
		return lastMessageId;
	}

	@Override
	public final String getLastAssertionId() {
		return lastAssertionId;
	}

	@Override
	public final List<Instant> getLastAssertionNotOnOrAfter() {
		return lastAssertionNotOnOrAfter;
	}

	@Override
	public final List<String> getErrors() {
		return errors;
	}

	public final String getErrorReason() {
		return errorReason;
	}

	@Override
	public final String getLastRequestId() {
		return lastRequestId;
	}

	public final String getLastRequest() {
		return lastRequest;
	}

	public final String getLastResponse() {
		return lastResponse;
	}

}