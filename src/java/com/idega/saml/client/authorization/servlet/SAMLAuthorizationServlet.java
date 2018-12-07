package com.idega.saml.client.authorization.servlet;

import java.io.IOException;
import java.util.Enumeration;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;

import com.idega.presentation.IWContext;
import com.idega.restful.servlet.DefaultRestfulServlet;
import com.idega.saml.client.authorization.service.SAMLAuthorizer;
import com.idega.util.CoreConstants;
import com.idega.util.CoreUtil;
import com.idega.util.StringHandler;
import com.idega.util.StringUtil;
import com.idega.util.WebUtil;
import com.idega.util.expression.ELUtil;

public class SAMLAuthorizationServlet extends DefaultRestfulServlet {

	private static final long serialVersionUID = 7664332448984779082L;

	private static final Logger LOGGER = Logger.getLogger(SAMLAuthorizationServlet.class.getName());

	@Autowired
	private SAMLAuthorizer authorizer;

	@Autowired
	private WebUtil webUtil;

	private SAMLAuthorizer getAuthorizer() {
		if (authorizer == null) {
			ELUtil.getInstance().autowire(this);
		}
		return authorizer;
	}

	private WebUtil getWebUtil() {
		if (webUtil == null) {
			ELUtil.getInstance().autowire(this);
		}
		return webUtil;
	}

	private void doLogout(IWContext iwc, HttpServletResponse response) throws ServletException, IOException {
		if (getAuthorizer().isDebug()) {
			Enumeration<String> params = iwc.getParameterNames();
			if (params != null) {
				while (params.hasMoreElements()) {
					String param = params.nextElement();
					String value = iwc.getParameter(param);
					LOGGER.info("Param '" + param + "' = '" + value + "'");
				}
			}
		}

		if (iwc.isLoggedOn()) {
			getWebUtil().logOut();
		}

		response.sendRedirect(CoreConstants.SLASH);
	}

	private void doLogin(HttpServletRequest request, HttpServletResponse response, String requestURI) throws ServletException, IOException {
		String type = StringHandler.replace(requestURI, "/authorization/acs", CoreConstants.EMPTY);
		type = type == null ? type : StringHandler.replace(type, CoreConstants.SLASH, CoreConstants.EMPTY);
		type = StringUtil.isEmpty(type) ? null : type;
		if (StringUtil.isEmpty(type)) {
			type = request.getParameter("type");
		}

		if (getAuthorizer().isDebug()) {
			LOGGER.info("Type: " + type);
		}

		String url = getAuthorizer().getRedirectURLAfterProcessedResponse(request, response, type);
		if (StringUtil.isEmpty(url)) {
			url = CoreUtil.getServerURL(request);
		}

		response.sendRedirect(url);
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doHandleRequest(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doHandleRequest(request, response);
	}

	private void doHandleRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		IWContext iwc = CoreUtil.getIWContext();
		if (iwc == null) {
			iwc = new IWContext(request, response, getServletContext());
		}

		String requestURI = request.getRequestURI();

		boolean debug = getAuthorizer().isDebug();

		boolean login = isLogin(requestURI);
		boolean logout = isLogout(requestURI);
		if (debug) {
			LOGGER.info("Request URI: " + requestURI + ", login: " + login + ", logout: " + logout);
		}

		if (login) {
			doLogin(request, response, requestURI);
		} else if (logout) {
			doLogout(iwc, response);
		}
	}

	private boolean isLogin(String uri) {
		if (StringUtil.isEmpty(uri)) {
			return false;
		}

		return uri.startsWith("/authorization/acs");
	}

	private boolean isLogout(String uri) {
		if (StringUtil.isEmpty(uri)) {
			return false;
		}

		return uri.startsWith("/authorization/slo");
	}

	private boolean isValidURI(String uri) {
		if (StringUtil.isEmpty(uri)) {
			return false;
		}

		return isLogin(uri) || isLogout(uri);
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		if (
				request instanceof HttpServletRequest &&
				isValidURI(((HttpServletRequest) request).getRequestURI()) &&
				response instanceof HttpServletResponse
		) {
			doHandleRequest((HttpServletRequest) request, (HttpServletResponse) response);
			return;
		}

		super.doFilter(request, response, chain);
	}

}