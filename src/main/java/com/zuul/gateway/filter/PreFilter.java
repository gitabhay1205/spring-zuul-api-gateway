package com.zuul.gateway.filter;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.zuul.gateway.JwtTokenGenerator;

@Component
public class PreFilter extends ZuulFilter {

	@Autowired
	private JwtTokenGenerator jwtTokenGenerator;

	@Override
	public boolean shouldFilter() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public String filterType() {
		// TODO Auto-generated method stub
		return "pre";
	}

	@Override
	public int filterOrder() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Object run() throws ZuulException {

		RequestContext request = RequestContext.getCurrentContext();
		HttpServletRequest httpRequest = request.getRequest();

		try {

			String client_id = httpRequest.getHeader("client_id");
			String client_secret = httpRequest.getHeader("client_secret");
			String authorization = httpRequest.getHeader("authorization");
			String oldToken = null;

			if (StringUtils.isBlank(client_id) || StringUtils.isBlank(client_secret)
					|| StringUtils.isBlank(authorization)) {

				request.setResponseStatusCode(417);
				request.setResponseBody(
						"{ \" Error\" :\" client_id, client_secret of authorization cannot be blank \"}");

				throw new ZuulException(
						"Expectation Failed 1 :client_id, client_secret of authorization cannot be blank", 417,
						"client_id, client_secret of authorization cannot be blank");
			}

			if (isAuthenticated(client_id, client_secret)) {

				if (!authorization.startsWith("Bearer")) {

					request.setResponseStatusCode(417);
					request.setResponseBody("{ \" Error\" :\" Authorization Should start with Bearer \"}");

					throw new ZuulException("Expectation Failed 2 : Authorization Should start with Bearer", 417,
							"Authorization Should start with Bearer");

				} else {

					oldToken = authorization.substring(6).trim();

					// Checking if Old Token is Empty, then create a new token
					if (oldToken != null && oldToken.isEmpty()) {

						String token = this.jwtTokenGenerator.generateJwt(client_id);
						System.out.println("Generated Token is " + token);
						request.addZuulRequestHeader("Authorization", "Bearer " + token);
						request.addZuulResponseHeader("Authorization", "Bearer " + token);

						// Checking If token is expired
					} else if (this.jwtTokenGenerator.isJwtTokenExpired(oldToken)) {

						System.out.println("Old Token is expired and generating new Token");
						String token = this.jwtTokenGenerator.generateJwt(client_id);
						System.out.println("Generated Token is " + token);
						request.addZuulRequestHeader("Authorization", "Bearer " + token);
						request.addZuulResponseHeader("Authorization", "Bearer " + token);

					} else {
						request.addZuulRequestHeader("Authorization", "Bearer " + oldToken);
						request.addZuulResponseHeader("Authorization", "Bearer " + oldToken);
					}
					return null;
				}
			} else {

				request.setResponseStatusCode(400);
				request.setResponseBody("{ \" Error\" :\" client_id, client_secret are invalid \"}");

				throw new ZuulException("Expectation Failed 1 :client_id, client_secret are invalid", 400,
						"client_id, client_secret are invalid");
			}
		} catch (Throwable e) {

			System.out.println(e.toString());

		}
		return null;
	}

	// Checking Client id and Secret, we can also use Jdbc or Ldap to authenticate
	// credentials
	private boolean isAuthenticated(String client_id, String client_secret) {

		if (client_id.equals("clientid") && client_secret.equals("clientpassword")) {

			return true;
		} else
			return false;
	}

}
