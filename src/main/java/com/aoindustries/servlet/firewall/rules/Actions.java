/*
 * ao-servlet-firewall-rules - Rules for servlet-based application request filtering.
 * Copyright (C) 2018  AO Industries, Inc.
 *     support@aoindustries.com
 *     7262 Bull Pen Cir
 *     Mobile, AL 36695
 *
 * This file is part of ao-servlet-firewall-rules.
 *
 * ao-servlet-firewall-rules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ao-servlet-firewall-rules is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ao-servlet-firewall-rules.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aoindustries.servlet.firewall.rules;

import com.aoindustries.net.Path;
import com.aoindustries.net.pathspace.Prefix;
import java.io.IOException;
import javax.servlet.ServletException;

/**
 * A set of simple {@link Action} implementations.
 */
public class Actions {

	private Actions() {}

	// <editor-fold defaultstate="collapsed" desc="General">
	/**
	 * Performs no action.
	 */
	public static final Action NOOP = new Action() {
		@Override
		public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) {
			return false;
		}
	};

	/**
	 * Performs no action and terminates request processing.
	 */
	public static final Action EXIT = new Action() {
		@Override
		public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) {
			return true;
		}
	};

	// TODO: Options to throw exceptions? IOException, ServletException, SkipPageException (wrapped)

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="FilterChain">
	/**
	 * @see  javax.servlet.FilterChain
	 */
	public static class FilterChain {

		private FilterChain() {}

		/**
		 * @see  FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
		 */
		public static final Action doFilter = new Action() {
			@Override
			public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) throws IOException, ServletException {
				chain.doFilter(request, response);
				return true;
			}
		};
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="ServletContext">
	/**
	 * @see  javax.servlet.ServletContext
	 */
	public static class ServletContext {

		private ServletContext() {}

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: NamedDispatcher?

		// TODO: RequestDispatcher?

		/**
		 * @see  javax.servlet.ServletContext#log(java.lang.String)
		 */
		public static final Action LOG = new Action() {
			@Override
			public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) {
				// TODO: Could log more
				request.getServletContext().log("prefix = " + prefix + ", prefixPath = " + prefixPath + ", path = " + path);
				return false;
			}
		};

		/**
		 * @see  javax.servlet.ServletContext#log(java.lang.String)
		 */
		public static Action log(final String message) {
			return new Action() {
				@Override
				public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) {
					// TODO: Could log more or less
					request.getServletContext().log("prefix = " + prefix + ", prefixPath = " + prefixPath + ", path = " + path + ", message = " + message);
					return false;
				}
			};
		}
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="ServletRequest">
	/**
	 * @see  javax.servlet.ServletRequest
	 */
	public static class ServletRequest {

		private ServletRequest() {}

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: setCharacterEncoding?

		// TODO: startAsync?
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="HttpServletRequest">
	/**
	 * @see  javax.servlet.http.HttpServletRequest
	 */
	public static class HttpServletRequest {

		private HttpServletRequest() {}

		// TODO: Authenticate?

		// TODO: Parts?

		// TODO: login?

		/**
		 * @see  javax.servlet.http.HttpServletRequest#logout()
		 */
		public static final Action LOGOUT = new Action() {
			@Override
			public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) throws IOException, ServletException {
				request.logout();
				return false;
			}
		};
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="ServletResponse">
	/**
	 * @see  javax.servlet.ServletResponse
	 */
	public static class ServletResponse {

		private ServletResponse() {}

		// TODO: flushBuffer?

		// TODO: reset?

		// TODO: resetBuffer?

		// TODO: setBufferSize?

		// TODO: setCharacterEncoding?

		// TODO: setContentLength?

		// TODO: setContentType?

		// TODO: setLocale?
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="HttpServletResponse">
	/**
	 * @see  HttpServletResponse
	 */
	public static class HttpServletResponse {

		private HttpServletResponse() {}

		// TODO: addCookie?

		// TODO: headers

		/**
		 * @see  javax.servlet.http.HttpServletResponse#sendError(int)
		 */
		public static class sendError {

			private sendError() {}

			/**
			 * Sends the provided HTTP status code.
			 *
			 * @see  javax.servlet.http.HttpServletResponse#sendError(int)
			 */
			public static final Action sendError(final int sc) {
				return new Action() {
					@Override
					public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) throws IOException, ServletException {
						response.sendError(sc);
						return true;
					}
				};
			}

			/**
			 * Sends the provided HTTP status code and provided message.
			 *
			 * @see  javax.servlet.http.HttpServletResponse#sendError(int, java.lang.String)
			 */
			public static final Action sendError(final int sc, final String message) {
				return new Action() {
					@Override
					public boolean perform(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain, Prefix prefix, Path prefixPath, Path path) throws IOException, ServletException {
						response.sendError(sc, message);
						return true;
					}
				};
			}

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_ACCEPTED
			 */
			public static final Action ACCEPTED = sendError(javax.servlet.http.HttpServletResponse.SC_ACCEPTED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_BAD_GATEWAY
			 */
			public static final Action BAD_GATEWAY = sendError(javax.servlet.http.HttpServletResponse.SC_BAD_GATEWAY);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_BAD_REQUEST
			 */
			public static final Action BAD_REQUEST = sendError(javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_CONFLICT
			 */
			public static final Action CONFLICT = sendError(javax.servlet.http.HttpServletResponse.SC_CONFLICT);

			/**
			 * TODO: Does this make sense as sendError?
			 *
			 * @see  javax.servlet.http.HttpServletResponse#SC_CONTINUE
			 */
			public static final Action CONTINUE = sendError(javax.servlet.http.HttpServletResponse.SC_CONTINUE);

			/**
			 * TODO: Does this make sense as sendError?
			 *
			 * @see  javax.servlet.http.HttpServletResponse#SC_CREATED
			 */
			public static final Action CREATED = sendError(javax.servlet.http.HttpServletResponse.SC_CREATED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_EXPECTATION_FAILED
			 */
			public static final Action EXPECTATION_FAILED = sendError(javax.servlet.http.HttpServletResponse.SC_EXPECTATION_FAILED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_FORBIDDEN
			 */
			public static final Action FORBIDDEN = sendError(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_FOUND
			 */
			public static final Action FOUND = sendError(javax.servlet.http.HttpServletResponse.SC_FOUND);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_GATEWAY_TIMEOUT
			 */
			public static final Action GATEWAY_TIMEOUT = sendError(javax.servlet.http.HttpServletResponse.SC_GATEWAY_TIMEOUT);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_GONE
			 */
			public static final Action GONE = sendError(javax.servlet.http.HttpServletResponse.SC_GONE);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_HTTP_VERSION_NOT_SUPPORTED
			 */
			public static final Action HTTP_VERSION_NOT_SUPPORTED = sendError(javax.servlet.http.HttpServletResponse.SC_HTTP_VERSION_NOT_SUPPORTED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_INTERNAL_SERVER_ERROR
			 */
			public static final Action INTERNAL_SERVER_ERROR = sendError(javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_LENGTH_REQUIRED
			 */
			public static final Action LENGTH_REQUIRED = sendError(javax.servlet.http.HttpServletResponse.SC_LENGTH_REQUIRED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_METHOD_NOT_ALLOWED
			 */
			public static final Action METHOD_NOT_ALLOWED = sendError(javax.servlet.http.HttpServletResponse.SC_METHOD_NOT_ALLOWED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_MOVED_PERMANENTLY
			 */
			public static final Action MOVED_PERMANENTLY = sendError(javax.servlet.http.HttpServletResponse.SC_MOVED_PERMANENTLY);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_MOVED_TEMPORARILY
			 */
			public static final Action MOVED_TEMPORARILY = sendError(javax.servlet.http.HttpServletResponse.SC_MOVED_TEMPORARILY);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_MULTIPLE_CHOICES
			 */
			public static final Action MULTIPLE_CHOICES = sendError(javax.servlet.http.HttpServletResponse.SC_MULTIPLE_CHOICES);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_NO_CONTENT
			 */
			public static final Action NO_CONTENT = sendError(javax.servlet.http.HttpServletResponse.SC_NO_CONTENT);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_NON_AUTHORITATIVE_INFORMATION
			 */
			public static final Action NON_AUTHORITATIVE_INFORMATION = sendError(javax.servlet.http.HttpServletResponse.SC_NON_AUTHORITATIVE_INFORMATION);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_NOT_ACCEPTABLE
			 */
			public static final Action NOT_ACCEPTABLE = sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_NOT_FOUND
			 */
			public static final Action NOT_FOUND = sendError(javax.servlet.http.HttpServletResponse.SC_NOT_FOUND);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_NOT_IMPLEMENTED
			 */
			public static final Action NOT_IMPLEMENTED = sendError(javax.servlet.http.HttpServletResponse.SC_NOT_IMPLEMENTED);

			/**
			 * TODO: Does this make sense as sendError?
			 *
			 * @see  javax.servlet.http.HttpServletResponse#SC_NOT_MODIFIED
			 */
			public static final Action NOT_MODIFIED = sendError(javax.servlet.http.HttpServletResponse.SC_NOT_MODIFIED);

			/**
			 * TODO: Does this make sense as sendError?
			 *
			 * @see  javax.servlet.http.HttpServletResponse#SC_OK
			 */
			public static final Action OK = sendError(javax.servlet.http.HttpServletResponse.SC_OK);

			/**
			 * TODO: Does this make sense as sendError?
			 *
			 * @see  javax.servlet.http.HttpServletResponse#SC_PARTIAL_CONTENT
			 */
			public static final Action PARTIAL_CONTENT = sendError(javax.servlet.http.HttpServletResponse.SC_PARTIAL_CONTENT);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_PAYMENT_REQUIRED
			 */
			public static final Action PAYMENT_REQUIRED = sendError(javax.servlet.http.HttpServletResponse.SC_PAYMENT_REQUIRED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_PRECONDITION_FAILED
			 */
			public static final Action PRECONDITION_FAILED = sendError(javax.servlet.http.HttpServletResponse.SC_PRECONDITION_FAILED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_PROXY_AUTHENTICATION_REQUIRED
			 */
			public static final Action PROXY_AUTHENTICATION_REQUIRED = sendError(javax.servlet.http.HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_REQUEST_ENTITY_TOO_LARGE
			 */
			public static final Action REQUEST_ENTITY_TOO_LARGE = sendError(javax.servlet.http.HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_REQUEST_TIMEOUT
			 */
			public static final Action REQUEST_TIMEOUT = sendError(javax.servlet.http.HttpServletResponse.SC_REQUEST_TIMEOUT);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_REQUEST_URI_TOO_LONG
			 */
			public static final Action REQUEST_URI_TOO_LONG = sendError(javax.servlet.http.HttpServletResponse.SC_REQUEST_URI_TOO_LONG);

			/**
			 * TODO: Does this make sense as sendError?
			 *
			 * @see  javax.servlet.http.HttpServletResponse#SC_REQUESTED_RANGE_NOT_SATISFIABLE
			 */
			public static final Action REQUESTED_RANGE_NOT_SATISFIABLE = sendError(javax.servlet.http.HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_RESET_CONTENT
			 */
			public static final Action RESET_CONTENT = sendError(javax.servlet.http.HttpServletResponse.SC_RESET_CONTENT);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_SEE_OTHER
			 */
			public static final Action SEE_OTHER = sendError(javax.servlet.http.HttpServletResponse.SC_SEE_OTHER);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_SERVICE_UNAVAILABLE
			 */
			public static final Action SERVICE_UNAVAILABLE = sendError(javax.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_SWITCHING_PROTOCOLS
			 */
			public static final Action SWITCHING_PROTOCOLS = sendError(javax.servlet.http.HttpServletResponse.SC_SWITCHING_PROTOCOLS);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_TEMPORARY_REDIRECT
			 */
			public static final Action TEMPORARY_REDIRECT = sendError(javax.servlet.http.HttpServletResponse.SC_TEMPORARY_REDIRECT);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_UNAUTHORIZED
			 */
			public static final Action UNAUTHORIZED = sendError(javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_UNSUPPORTED_MEDIA_TYPE
			 */
			public static final Action UNSUPPORTED_MEDIA_TYPE = sendError(javax.servlet.http.HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);

			/**
			 * @see  javax.servlet.http.HttpServletResponse#SC_USE_PROXY
			 */
			public static final Action USE_PROXY = sendError(javax.servlet.http.HttpServletResponse.SC_USE_PROXY);
		}

		// TODO: sendRedirect

		// TODO: setStatus
	}
	// </editor-fold>

	// TODO: Cookies?

	// TODO: HttpSession?
}
