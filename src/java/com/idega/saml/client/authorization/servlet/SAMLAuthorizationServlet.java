package com.idega.saml.client.authorization.servlet;

import java.io.IOException;
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
import com.idega.util.expression.ELUtil;

public class SAMLAuthorizationServlet extends DefaultRestfulServlet {

	private static final long serialVersionUID = 7664332448984779082L;

	@Autowired
	private SAMLAuthorizer authorizer;

	private SAMLAuthorizer getAuthorizer() {
		if (authorizer == null) {
			ELUtil.getInstance().autowire(this);
		}
		return authorizer;
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		IWContext iwc = CoreUtil.getIWContext();
		if (iwc == null) {
			iwc = new IWContext(request, response, getServletContext());
		}

		String requestURI = request.getRequestURI();
		String type = StringHandler.replace(requestURI, "/authorization/acs", CoreConstants.EMPTY);
		type = type == null ? type : StringHandler.replace(type, CoreConstants.SLASH, CoreConstants.EMPTY);
		type = StringUtil.isEmpty(type) ? null : type;

		Logger.getLogger(getClass().getName()).info("Type: " + type);

		String url = getAuthorizer().getRedirectURLAfterProcessedResponse(request, response, type);
		if (StringUtil.isEmpty(url)) {
			url = CoreUtil.getServerURL(request);
		}

		response.sendRedirect(url);
	}

	private boolean isValidURI(String uri) {
		if (StringUtil.isEmpty(uri)) {
			return false;
		}

		return uri.startsWith("/authorization/slo") || uri.startsWith("/authorization/acs");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		if (
				request instanceof HttpServletRequest &&
				isValidURI(((HttpServletRequest) request).getRequestURI()) &&
				response instanceof HttpServletResponse
		) {
			doPost((HttpServletRequest) request, (HttpServletResponse) response);
			return;
		}

		super.doFilter(request, response, chain);
	}

}