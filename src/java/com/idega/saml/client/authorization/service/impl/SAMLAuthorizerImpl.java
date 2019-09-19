package com.idega.saml.client.authorization.service.impl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import com.idega.block.sso.model.AuthorizationSettings;
import com.idega.core.accesscontrol.business.LoggedOnInfo;
import com.idega.core.accesscontrol.business.LoginBusinessBean;
import com.idega.core.accesscontrol.event.LoggedInUserCredentials;
import com.idega.core.accesscontrol.event.LoggedInUserCredentials.LoginType;
import com.idega.core.business.DefaultSpringBean;
import com.idega.idegaweb.IWMainApplicationSettings;
import com.idega.presentation.IWContext;
import com.idega.saml.client.authorization.service.IdegaSamlAuth;
import com.idega.saml.client.authorization.service.SAMLAuthorizer;
import com.idega.servlet.filter.RequestResponseProvider;
import com.idega.user.business.UserBusiness;
import com.idega.user.data.User;
import com.idega.util.CoreConstants;
import com.idega.util.CoreUtil;
import com.idega.util.EmailValidator;
import com.idega.util.IOUtil;
import com.idega.util.ListUtil;
import com.idega.util.StringHandler;
import com.idega.util.StringUtil;
import com.idega.util.datastructures.map.MapUtil;
import com.idega.util.expression.ELUtil;
import com.idega.util.xml.XmlUtil;
import com.onelogin.saml2.Auth;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;

import is.idega.idegaweb.egov.accounting.business.CitizenBusiness;

@Service
@Scope(BeanDefinition.SCOPE_SINGLETON)
public class SAMLAuthorizerImpl extends DefaultSpringBean implements SAMLAuthorizer {

	private static final String ATTR_NAME_ID = "saml_name_id",
								ATTR_SESSION_INDEX = "saml_session_index";

	@Override
	public boolean isDebug() {
		return getSettings().getBoolean("saml_debug", false);
	}

	@Override
	public void doSendAuthorizationRequest(AuthorizationSettings settings, HttpServletRequest request, HttpServletResponse response, String type) throws Exception {
		if (settings == null || request == null || response == null) {
			getLogger().warning("Invalid parameters");
			return;
		}

		String authGateway = settings.getRemoteLoginService();
		String returnURL = settings.getRemoteLoginReturn();

		if (isDebug()) {
			getLogger().info("authGateway: " + authGateway + ", returnURL: " + returnURL + ", type: " + type);
		}

		Saml2Settings samlSettings = getSAMLSettings(request, type);
		if (samlSettings == null) {
			getLogger().warning("Invalid SAML settings, can not authorize via " + authGateway);
			return;
		}

		Auth auth = new Auth(samlSettings, request, response);
		auth.login(returnURL);
	}

	private Map<String, List<String>> getAttributes(String samlResponse) {
		if (StringUtil.isEmpty(samlResponse)) {
			return null;
		}

		try {
			Document doc = XmlUtil.getJDOMXMLDocument(samlResponse);
			if (doc == null) {
				return null;
			}

			List<Element> attributesElements = XmlUtil.getElementsByXPath(doc.getRootElement(), "Attribute");
			if (ListUtil.isEmpty(attributesElements)) {
				return null;
			}

			Map<String, List<String>> results = new HashMap<>();
			for (Element attributeElement: attributesElements) {
				Attribute name = attributeElement.getAttribute("Name");
				if (name == null) {
					continue;
				}

				String attrValue = name.getValue();
				if (StringUtil.isEmpty(attrValue)) {
					continue;
				}

				List<Element> values = XmlUtil.getElementsByXPath(attributeElement, "AttributeValue");
				if (ListUtil.isEmpty(values)) {
					continue;
				}

				Set<String> uniqueValues = new HashSet<>();
				for (Element valueElement: values) {
					String value = valueElement.getText();
					if (!StringUtil.isEmpty(value)) {
						uniqueValues.add(value);
					}
				}

				List<String> attrValues = results.get(attrValue);
				if (attrValues == null) {
					attrValues = new ArrayList<>(uniqueValues);
					results.put(attrValue, attrValues);
				} else {
					attrValues.addAll(uniqueValues);
				}
			}
			return results;
		} catch (Exception e) {
			getLogger().log(Level.WARNING, "Error getting attributes from\n" + samlResponse, e);
		}
		return null;
	}

	@Override
	public String getRedirectURLAfterProcessedResponse(HttpServletRequest request, HttpServletResponse response, String type) {
		String ip = null, hostname = null, decodedSAMLResponse = null;
		try {
			IWContext iwc = CoreUtil.getIWContext();
			ip = iwc == null ? null : iwc.getRemoteIpAddress();
			hostname = iwc == null ? null : iwc.getRemoteHostName();
			boolean debug = isDebug();
			if (debug) {
				getLogger().info("Received request (" + request.getRequestURI() + ") via " + request.getMethod() + " from IP: " + ip + " and hostname: " + hostname +
						". Type: " + (StringUtil.isEmpty(type) ? "unknown" : type));
			}

			Saml2Settings settings = getSAMLSettings(request, type);
			Auth auth = new IdegaSamlAuth(settings, request, response);

			String samlResponseParameter = request.getParameter("SAMLResponse");
			if (debug) {
				getLogger().info("Starting to process response:\n" + samlResponseParameter);
			}
			if (!StringUtil.isEmpty(samlResponseParameter)) {
				decodedSAMLResponse = new String(Base64.getDecoder().decode(samlResponseParameter.getBytes(CoreConstants.ENCODING_UTF8)), CoreConstants.ENCODING_UTF8);
			}

			auth.processResponse();

			String nameId = auth.getNameId();
			String sessionIndex = auth.getSessionIndex();

			if (debug) {
				getLogger().info("Finished processing response:\n" + decodedSAMLResponse);
			}

			List<String> errors = auth.getErrors();
			if (ListUtil.isEmpty(errors)) {
				if (debug) {
					getLogger().info("No errors in\n" + decodedSAMLResponse);
				}
			} else {
				if (debug) {
					getLogger().warning("Failed to authenticate via SAML. Error(s):\n" + errors + "\nError reason: " + auth.getLastErrorReason() + "\nResponse:\n" + decodedSAMLResponse);
				}
				return null;
			}

			Map<String, List<String>> attributes = auth.getAttributes();
			if (MapUtil.isEmpty(attributes) && !StringUtil.isEmpty(decodedSAMLResponse)) {
				attributes = getAttributes(decodedSAMLResponse);
			}
			if (MapUtil.isEmpty(attributes)) {
				getLogger().warning("No attributes in SAML response:\n" + decodedSAMLResponse);
				return null;
			}

			String server = CoreUtil.getServerURL(request);
			if (server == null) {
				getLogger().warning("Unknown server. Attributes in response from SAML:\n" + attributes);
				return null;
			}

			if (debug) {
				getLogger().info("Attributes in response from SAML:\n" + attributes);
			}
			List<String> personalIds = attributes.get("urn:oid:1.3.6.1.4.1.2428.90.1.5");
			if (ListUtil.isEmpty(personalIds)) {
				personalIds = attributes.get("personalIdentityNumber");
			}
			if (ListUtil.isEmpty(personalIds)) {
				getLogger().warning("Failed to get personal ID of authenticated person from attributes " + attributes + " and SAML response:\n" + decodedSAMLResponse);
				return null;
			}
			String personalId = personalIds.iterator().next();
			if (StringUtil.isEmpty(personalId)) {
				getLogger().warning("Failed to get personal ID of authenticated person from " + personalIds);
				return null;
			}

			List<String> fullNames = attributes.get("name");
			if (ListUtil.isEmpty(fullNames)) {
				getLogger().warning("Failed to get full name of authenticated person from attributes " + attributes + " and SAML response:\n" + decodedSAMLResponse);
				return null;
			}
			String fullName = fullNames.iterator().next();
			if (StringUtil.isEmpty(fullName)) {
				getLogger().warning("Failed to get full name of authenticated person from " + fullNames);
				return null;
			}

			String homePage = getHomePage(iwc, personalId, fullName, type);
			if (StringUtil.isEmpty(homePage)) {
				getLogger().warning("Failed to get home page for " + fullName + " (personal ID: " + personalId + "). Login type: " + type);
				return null;
			}

			HttpSession session = iwc == null ? null : iwc.getSession();
			if (session == null) {
				if (request != null) {
					session = request.getSession();
				}
				if (session == null) {
					RequestResponseProvider rrProvider = null;
					try {
						rrProvider = ELUtil.getInstance().getBean(RequestResponseProvider.class);
					} catch (Exception e) {}
					HttpServletRequest httpRequest = rrProvider == null ? null : rrProvider.getRequest();
					if (httpRequest != null) {
						session = httpRequest.getSession();
					}
				}
			}
			if (session != null && !StringUtil.isEmpty(type)) {
				session.setAttribute(LoggedInUserCredentials.LOGIN_TYPE, type.concat(CoreConstants.AT).concat(LoginType.AUTHENTICATION_GATEWAY.toString()));
			}

			String email = null;
			User user = null;
			try {
				email = attributes.containsKey("mail") ? attributes.get("mail").get(0) : null;
				if (EmailValidator.getInstance().isValid(email)) {
					UserBusiness userBusiness = getServiceInstance(UserBusiness.class);
					user = userBusiness.getUser(personalId);
					userBusiness.updateUserMail(user, email);
				}
			} catch (Exception e) {
				getLogger().log(Level.WARNING, "Error updating email (" + email + ") for " + user + " (personal ID: " + personalId + ")", e);
			}

			boolean loginTypeStored = false;
			if (!StringUtil.isEmpty(type) && iwc.isLoggedOn()) {
				LoggedOnInfo loggedOnInfo = LoginBusinessBean.getLoggedOnInfo(iwc);
				if (loggedOnInfo != null) {
					loggedOnInfo.setLoginType(type.concat(CoreConstants.AT).concat(LoginType.AUTHENTICATION_GATEWAY.toString()));
					loginTypeStored = true;
				}
			}
			if (debug) {
				if (loginTypeStored) {
					getLogger().info("Login type '" + type + "' stored");
				} else {
					getLogger().warning("Login type '" + type + "' was not stored");
				}
			}

			if (server.endsWith(CoreConstants.SLASH)) {
				server = server.substring(0, server.length() - 1);
			}
			String redirect = server + homePage;
			redirect = redirect.concat("&type=").concat(type);

			if (debug) {
				getLogger().info("Redirect to " + redirect);
			}

			if (session != null) {
				session.setAttribute(ATTR_NAME_ID, nameId);
				session.setAttribute(ATTR_SESSION_INDEX, sessionIndex);
			}

			return redirect;
		} catch (Throwable e) {
			getLogger().log(Level.WARNING, "Error processing response from IP: " + ip + ", hostname: " + hostname + ". SAML response:\n" + decodedSAMLResponse, e);
		}

		return null;
	}

	private String getHomePage(IWContext iwc, String personalId, String fullName, String loginType) {
		CitizenBusiness citizenBusiness = getServiceInstance(iwc, CitizenBusiness.class);
		return citizenBusiness.getHomePageForCitizen(iwc, personalId, fullName, "saml2_authorizer.home_page", getApplicationProperty("saml2_oauth.cookie"), loginType);
	}

	private Saml2Settings getSAMLSettings(HttpServletRequest request, String type) {
		String server = CoreUtil.getHost(false);
		if (server == null) {
			getLogger().warning("Server is unknown");
			return null;
		}

		boolean debug = isDebug();
		server = server.toLowerCase();
		if (server.startsWith("http://")) {
			server = StringHandler.replace(server, "http://", "https://");
		}
		if (server.endsWith(CoreConstants.SLASH)) {
			server = server.substring(0, server.length() - 1);
		}
		if (debug) {
			getLogger().info("Server: '" + server + "'");
		}

		IWMainApplicationSettings appSettings = getSettings();

		Map<String, Object> samlData = new HashMap<>();

		String spProviderProp = SettingsBuilder.SP_ENTITYID_PROPERTY_KEY + (StringUtil.isEmpty(type) ? CoreConstants.EMPTY : CoreConstants.UNDER.concat(type));
		String serviceProviderId = appSettings.getProperty(spProviderProp, server);
		if (debug) {
			getLogger().info("Service provider ID for type " + type + ": " + serviceProviderId);
		}
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

		if (debug) {
			getLogger().info("Return url: " + url + " for type " + type);
		}
		samlData.put(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, url);

		samlData.put(SettingsBuilder.SECURITY_WANT_XML_VALIDATION, appSettings.getBoolean(SettingsBuilder.SECURITY_WANT_XML_VALIDATION, true));
		samlData.put(SettingsBuilder.SECURITY_SIGN_METADATA, appSettings.getBoolean(SettingsBuilder.SECURITY_SIGN_METADATA, false));

		samlData.put(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXT, appSettings.getProperty(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXT, "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"));
		samlData.put(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON, appSettings.getProperty(SettingsBuilder.SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON, "minimum"));

		String logoutURL = appSettings.getProperty(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY);
		if (StringUtil.isEmpty(logoutURL)) {
			getLogger().warning("Unknown logout URL, using " + identificationProviderId);
			logoutURL = identificationProviderId;
		}
		samlData.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, logoutURL);
		Boolean signLogout = appSettings.getBoolean(SettingsBuilder.SECURITY_LOGOUTREQUEST_SIGNED, Boolean.TRUE);
		if (signLogout != null) {
			samlData.put(SettingsBuilder.SECURITY_LOGOUTREQUEST_SIGNED, signLogout);
			if (signLogout) {
				Certificate logoutCertificate = getCertificate("saml2.cert_bundle_id", "saml2.logout_cert_path_within_bundle");
				if (logoutCertificate == null) {
					if (debug) {
						getLogger().warning("Logout certificate is not available for login type " + type);
					}
				} else {
					samlData.put(SettingsBuilder.SP_X509CERT_PROPERTY_KEY, logoutCertificate);
				}

				String spPathToPrivateKey = appSettings.getProperty("saml2.logout_cert_key");
				if (!StringUtil.isEmpty(spPathToPrivateKey)) {
					try {
						String spPrivateKey = StringHandler.getContentFromInputStream(
								IOUtil.getStreamFromJar(appSettings.getProperty("saml2.cert_bundle_id"), spPathToPrivateKey)
						);
						if (!StringUtil.isEmpty(spPrivateKey)) {
							spPrivateKey = spPrivateKey.replace("-----BEGIN PRIVATE KEY-----", CoreConstants.EMPTY);
							spPrivateKey = spPrivateKey.replace("-----END PRIVATE KEY-----", CoreConstants.EMPTY);
							spPrivateKey = spPrivateKey.replaceAll("\\s+", CoreConstants.EMPTY);

							byte[] spPrivateKeyEncodedBytes = Base64.getDecoder().decode(spPrivateKey);

					        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(spPrivateKeyEncodedBytes);
					        KeyFactory kf = KeyFactory.getInstance("RSA");
					        PrivateKey privKey = kf.generatePrivate(keySpec);
							samlData.put(SettingsBuilder.SP_PRIVATEKEY_PROPERTY_KEY, privKey);
						}
					} catch (Exception e) {
						getLogger().log(Level.WARNING, "Error getting private key", e);
					}
				}
			}
		}

		Certificate certificate = getCertificate("saml2.cert_bundle_id", "saml2.cert_path_within_bundle");
		if (certificate == null) {
			if (debug) {
				getLogger().info("Certificate is not available for login type " + type);
			}
			samlData.put(SettingsBuilder.CERTFINGERPRINT_PROPERTY_KEY, Boolean.FALSE.toString());
		} else {
			if (debug) {
				getLogger().info("Certificate is available for login type " + type);
			}
			samlData.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, certificate);
		}

		SettingsBuilder builder = new SettingsBuilder();
		Saml2Settings settings = builder.fromValues(samlData).build();
		return settings;
	}

	private Certificate getCertificate(String bundleIdentifierPropValue, String pathWithinBundlePropValue) {
		return getCertificate(bundleIdentifierPropValue, pathWithinBundlePropValue, true);
	}

	private Certificate getCertificate(String bundleIdentifierPropValue, String pathWithinBundlePropValue, boolean reTryWithDecoded) {
		InputStream stream = null;
		String bundleIdentifierProp = null, pathWithinBundle = null;

		try {
			bundleIdentifierProp = getApplicationProperty(bundleIdentifierPropValue);
			pathWithinBundle = getApplicationProperty(pathWithinBundlePropValue);
			if (StringUtil.isEmpty(bundleIdentifierProp) || StringUtil.isEmpty(pathWithinBundle)) {
				return null;
			}

			stream = IOUtil.getStreamFromJar(bundleIdentifierProp, pathWithinBundle);
			if (!reTryWithDecoded) {
				String content = StringHandler.getContentFromInputStream(stream);
				if (content == null) {
					getLogger().warning("Failed to get content from " + pathWithinBundle + " from bundle " + bundleIdentifierProp);
					return null;
				}

				IOUtil.closeInputStream(stream);
				stream = new ByteArrayInputStream(Base64Utils.decode(content.getBytes(CoreConstants.ENCODING_UTF8)));
			}
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return certFactory.generateCertificate(stream);
		} catch (Exception e) {
			if (reTryWithDecoded) {
				return getCertificate(bundleIdentifierPropValue, pathWithinBundlePropValue, false);
			}

			getLogger().log(Level.WARNING, "Error getting certificate " + pathWithinBundle + " from bundle " + bundleIdentifierProp, e);
		} finally {
			IOUtil.close(stream);
		}

		return null;
	}

	@Override
	public String getLogoutRequestURL(AuthorizationSettings settings, HttpServletRequest request, HttpServletResponse response) throws Exception {
		String type = settings == null ? null : settings.getType();
		String defaultLogoutType = getApplication().getSettings().getProperty("saml2.default_logout_type", "mobile");
		type = StringUtil.isEmpty(defaultLogoutType) ? type : defaultLogoutType;
		Saml2Settings samlSettings = settings == null ? null : getSAMLSettings(request, type);
		if (samlSettings == null) {
			getLogger().warning("Invalid SAML settings, can not logout");
			return null;
		}

		try {
			String nameId = null, sessionIndex = null;
			HttpSession session = request.getSession(true);
			if (session != null) {
				nameId = (String) session.getAttribute(ATTR_NAME_ID);
				sessionIndex = (String) session.getAttribute(ATTR_SESSION_INDEX);
			}
			Auth auth = new Auth(samlSettings, request, response);
			String redirect = auth.logout(null, nameId, sessionIndex, Boolean.TRUE);
			getLogger().info("Redirect to " + redirect + " after logout");
			return redirect;
		} catch (Exception e) {
			getLogger().log(Level.WARNING, "Error logging out via SAML. Settings: " + settings, e);
		}

		return null;
	}

}