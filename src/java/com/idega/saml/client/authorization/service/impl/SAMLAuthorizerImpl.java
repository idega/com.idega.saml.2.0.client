package com.idega.saml.client.authorization.service.impl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import com.idega.core.business.DefaultSpringBean;
import com.idega.idegaweb.IWMainApplicationSettings;
import com.idega.presentation.IWContext;
import com.idega.saml.client.authorization.service.SAMLAuthorizer;
import com.idega.saml.client.model.AuthorizationSettings;
import com.idega.util.CoreConstants;
import com.idega.util.CoreUtil;
import com.idega.util.IOUtil;
import com.idega.util.ListUtil;
import com.idega.util.StringHandler;
import com.idega.util.StringUtil;
import com.idega.util.datastructures.map.MapUtil;
import com.onelogin.saml2.Auth;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;

import is.idega.idegaweb.egov.accounting.business.CitizenBusiness;

@Service
@Scope(BeanDefinition.SCOPE_SINGLETON)
public class SAMLAuthorizerImpl extends DefaultSpringBean implements SAMLAuthorizer {

	@Override
	public void doSendAuthorizationRequest(AuthorizationSettings settings, HttpServletRequest request, HttpServletResponse response, String type) throws Exception {
		if (settings == null || request == null || response == null) {
			getLogger().warning("Invalid parameters");
			return;
		}

		String authGateway = settings.getRemoteLoginService();
		String returnURL = settings.getRemoteLoginReturn();

		getLogger().info("authGateway: " + authGateway + ", returnURL: " + returnURL + ", type: " + type);

		Saml2Settings samlSettings = getSAMLSettings(request, type);
		if (samlSettings == null) {
			getLogger().warning("Invalid SAML settings, can not authorize via " + authGateway);
			return;
		}

		Auth auth = new Auth(samlSettings, request, response);
		auth.login(returnURL);
	}

	@Override
	public String getRedirectURLAfterProcessedResponse(HttpServletRequest request, HttpServletResponse response, String type) {
		String ip = null, hostname = null, decodedSAMLResponse = null;
		try {
			IWContext iwc = CoreUtil.getIWContext();
			ip = iwc == null ? null : iwc.getRemoteIpAddress();
			hostname = iwc == null ? null : iwc.getRemoteHostName();
			getLogger().info("Received request (" + request.getRequestURI() + ") via " + request.getMethod() + " from IP: " + ip + " and hostname: " + hostname +
					". Type: " + (StringUtil.isEmpty(type) ? "default" : type));

			Saml2Settings settings = getSAMLSettings(request, type);
			Auth auth = new Auth(settings, request, response);

			String samlResponseParameter = request.getParameter("SAMLResponse");
			getLogger().info("Starting to process response:\n" + samlResponseParameter);
			if (!StringUtil.isEmpty(samlResponseParameter)) {
				decodedSAMLResponse = new String(Base64.getDecoder().decode(samlResponseParameter.getBytes(CoreConstants.ENCODING_UTF8)), CoreConstants.ENCODING_UTF8);
			}

			auth.processResponse();

			getLogger().info("Finished processing response:\n" + decodedSAMLResponse);

			List<String> errors = auth.getErrors();
			if (ListUtil.isEmpty(errors)) {
				getLogger().info("No errors in\n" + decodedSAMLResponse);
			} else {
				getLogger().warning("Failed to authenticate via SAML. Error(s):\n" + errors + "\nResponse:\n" + decodedSAMLResponse);
				return null;
			}

			Map<String, List<String>> attributes = auth.getAttributes();
			if (MapUtil.isEmpty(attributes)) {
				getLogger().warning("No attributes in SAML response:\n" + decodedSAMLResponse);
				return null;
			}

			String server = CoreUtil.getServerURL(request);
			if (server == null) {
				getLogger().warning("Unknown server. Attributes in response from SAML:\n" + attributes);
				return null;
			}

			getLogger().info("Attributes in response from SAML:\n" + attributes);	//	TODO
			List<String> personalIds = attributes.get("urn:oid:1.3.6.1.4.1.2428.90.1.5");
			if (ListUtil.isEmpty(personalIds)) {
				getLogger().warning("Failed to get personal ID of authenticated person from SAML response:\n" + auth.getLastResponseXML());
				return null;
			}
			String personalId = personalIds.iterator().next();
			if (StringUtil.isEmpty(personalId)) {
				getLogger().warning("Failed to get personal ID of authenticated person from " + personalIds);
				return null;
			}

			List<String> fullNames = attributes.get("name");
			if (ListUtil.isEmpty(fullNames)) {
				getLogger().warning("Failed to get full name of authenticated person from SAML response:\n" + auth.getLastResponseXML());
				return null;
			}
			String fullName = fullNames.iterator().next();
			if (StringUtil.isEmpty(fullName)) {
				getLogger().warning("Failed to get full name of authenticated person from " + fullNames);
				return null;
			}

			String homePage = getHomePage(iwc, personalId, fullName);

			if (server.endsWith(CoreConstants.SLASH)) {
				server = server.substring(0, server.length() - 1);
			}
			return server + homePage;
		} catch (Throwable e) {
			getLogger().log(Level.WARNING, "Error processing response from IP: " + ip + ", hostname: " + hostname + ". SAML response:\n" + decodedSAMLResponse, e);
		}

		return null;
	}

	private String getHomePage(IWContext iwc, String personalId, String fullName) {
		CitizenBusiness citizenBusiness = getServiceInstance(iwc, CitizenBusiness.class);
		return citizenBusiness.getHomePageForCitizen(iwc, personalId, fullName, "saml2_authorizer.home_page", getApplicationProperty("saml2_oauth.cookie"));
	}

	private Saml2Settings getSAMLSettings(HttpServletRequest request, String type) {
		String server = CoreUtil.getHost(false);
		if (server == null) {
			getLogger().warning("Server is unknown");
			return null;
		} else {
			getLogger().info("Service for SAML settings: " + server);	//	TODO
		}

		server = server.toLowerCase();
		if (!server.startsWith("https://")) {
			server = StringHandler.replace(server, "http://", "https://");
		}

		if (server.endsWith(CoreConstants.SLASH)) {
			server = server.substring(0, server.length() - 1);
		}

		IWMainApplicationSettings appSettings = getSettings();

		Map<String, Object> samlData = new HashMap<>();

		String spProviderProp = SettingsBuilder.SP_ENTITYID_PROPERTY_KEY + (StringUtil.isEmpty(type) ? CoreConstants.EMPTY : CoreConstants.UNDER.concat(type));
		String serviceProviderId = appSettings.getProperty(spProviderProp, server);
		getLogger().info("Service provider ID for type " + type + ": " + serviceProviderId);
		samlData.put(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, serviceProviderId);

		String identificationProviderId = appSettings.getProperty(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY);
		samlData.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, identificationProviderId);

		String singleSignOnService = appSettings.getProperty(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY);
		samlData.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY, singleSignOnService);

		String acsURL = server.concat("/authorization/acs/");
		if (!StringUtil.isEmpty(type) && !type.equals("default")) {
			acsURL = acsURL.concat(type);
			if (!acsURL.endsWith(CoreConstants.SLASH)) {
				acsURL = acsURL.concat(CoreConstants.SLASH);
			}
		}
		URL url = null;
		try {
			url = new URL(acsURL);
		} catch (MalformedURLException e) {
			getLogger().warning("Invalid URL: " + acsURL);
		}
		if (url == null) {
			return null;
		}

		getLogger().info("Return url: " + url + " for type " + type);
		samlData.put(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, url);

		samlData.put(SettingsBuilder.SECURITY_WANT_XML_VALIDATION, appSettings.getBoolean(SettingsBuilder.SECURITY_WANT_XML_VALIDATION, true));
		samlData.put(SettingsBuilder.SECURITY_SIGN_METADATA, appSettings.getBoolean(SettingsBuilder.SECURITY_SIGN_METADATA, false));

		samlData.put(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXT, appSettings.getProperty(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXT, "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"));
		samlData.put(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON, appSettings.getProperty(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON, "minimum"));

		Certificate certificate = getCertificate();
		if (certificate == null) {
			samlData.put(SettingsBuilder.CERTFINGERPRINT_PROPERTY_KEY, Boolean.FALSE.toString());
		} else {
			samlData.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, certificate);
		}

		SettingsBuilder builder = new SettingsBuilder();
		Saml2Settings settings = builder.fromValues(samlData).build();
		return settings;
	}

	private Certificate getCertificate() {
		return getCertificate(true);
	}

	private Certificate getCertificate(boolean reTryWithDecoded) {
		InputStream stream = null;
		String bundleIdentifierProp = null, pathWithinBundle = null;

		try {
			bundleIdentifierProp = getApplicationProperty("saml2.cert_bundle_id");
			pathWithinBundle = getApplicationProperty("saml2.cert_path_within_bundle");
			if (StringUtil.isEmpty(bundleIdentifierProp) || StringUtil.isEmpty(pathWithinBundle)) {
				return null;
			}

			stream = IOUtil.getStreamFromJar(bundleIdentifierProp, pathWithinBundle);
			if (!reTryWithDecoded) {
				String content = StringHandler.getContentFromInputStream(stream);
				IOUtil.closeInputStream(stream);
				stream = new ByteArrayInputStream(Base64Utils.decode(content.getBytes(CoreConstants.ENCODING_UTF8)));
			}
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return certFactory.generateCertificate(stream);
		} catch (Exception e) {
			if (reTryWithDecoded) {
				return getCertificate(false);
			}

			getLogger().log(Level.WARNING, "Error getting certificate " + pathWithinBundle + " from bundle " + bundleIdentifierProp, e);
		} finally {
			IOUtil.close(stream);
		}

		return null;
	}

}