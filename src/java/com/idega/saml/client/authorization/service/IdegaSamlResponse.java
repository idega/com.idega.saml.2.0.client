package com.idega.saml.client.authorization.service;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Constants;

public class IdegaSamlResponse extends SamlResponse {

	public IdegaSamlResponse(Saml2Settings settings, HttpRequest request) throws XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException, ValidationError {
		super(settings, request);
	}

	/**
	 * Verifies that the document only contains a single Assertion (encrypted or not).
	 *
	 * @return true if the document passes.
	 *
	 * @throws IllegalArgumentException
	 */
	@Override
	public Boolean validateNumAssertions() throws IllegalArgumentException {
		if (!super.validateNumAssertions()) {
			Document samlResponseDocument = getSAMLResponseDocument();
			NodeList encryptedAssertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "EncryptedAssertion");
			NodeList assertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "Assertion");

			Boolean valid = assertionNodes.getLength() + encryptedAssertionNodes.getLength() >= 1;

			return valid;
		}
		return true;
	}

}