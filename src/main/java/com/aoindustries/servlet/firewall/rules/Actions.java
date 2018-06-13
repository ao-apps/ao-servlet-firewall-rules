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

import com.aoindustries.servlet.firewall.api.Action;
import com.aoindustries.servlet.firewall.api.Action.Result;
import com.aoindustries.servlet.firewall.api.FirewallContext;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A set of simple {@link Action} implementations.
 */
public class Actions {

	private Actions() {}

	// <editor-fold defaultstate="collapsed" desc="General">
	/**
	 * Performs no action.
	 *
	 * @return  {@link Result#CONTINUE} always
	 */
	public static final Action CONTINUE = new Action() {
		@Override
		public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
			return Result.CONTINUE;
		}
	};

	/**
	 * Performs no action and terminates request processing.
	 *
	 * @return  {@link Result#TERMINATE} always
	 */
	public static final Action TERMINATE = new Action() {
		@Override
		public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
			return Result.TERMINATE;
		}
	};

	// TODO: Options to throw exceptions? IOException, ServletException, SkipPageException (wrapped)

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="chain">
	/**
	 * @see  FilterChain
	 */
	public static class chain {

		private chain() {}

		/**
		 * @see  FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
		 *
		 * @return  {@link Result#TERMINATE} always
		 */
		public static final Action doFilter = new Action() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
				chain.doFilter(request, response);
				return Result.TERMINATE;
			}
		};
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="servletContext">
	/**
	 * @see  ServletContext
	 */
	public static class servletContext {

		private servletContext() {}

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: NamedDispatcher?

		// TODO: RequestDispatcher?

		/**
		 * @see  ServletContext#log(java.lang.String)
		 *
		 * @return  {@link Result#CONTINUE} always
		 */
		public static final Action log = new Action() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
				// TODO: Could log more
				// TODO: PathPrefix, if present.  Or a way for PathPrefix to register loggers on the FirewallContext
				// TODO: Also TRACE/stack/integration for logger on FirewallContext?
				request.getServletContext().log("request.servetPath = " + request.getServletPath()); // TODO: more + ", prefix = " + prefix + ", prefixPath = " + prefixPath + ", path = " + path);
				return Result.CONTINUE;
			}
		};

		/**
		 * @see  ServletContext#log(java.lang.String)
		 *
		 * @return  {@link Result#CONTINUE} always
		 */
		public static Action log(final String message) {
			return new Action() {
				@Override
				public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
					// TODO: Could log more or less
					request.getServletContext().log(message);
					return Result.CONTINUE;
				}
			};
		}
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="request">
	/**
	 * @see  javax.servlet.ServletRequest
	 */
	public static class request {

		private request() {}

		// <editor-fold defaultstate="collapsed" desc="ServletRequest">
		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: setCharacterEncoding?

		// TODO: startAsync?
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="HttpServletRequest">
		// TODO: Authenticate?

		// TODO: Parts?

		// TODO: login?

		/**
		 * @see  HttpServletRequest#logout()
		 *
		 * @return  {@link Result#CONTINUE} always
		 */
		public static final Action logout = new Action() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException {
				request.logout();
				return Result.CONTINUE;
			}
		};
		// </editor-fold>
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="response">
	/**
	 * @see  ServletResponse
	 * @see  HttpServletResponse
	 */
	public static class response {

		private response() {}

		// <editor-fold defaultstate="collapsed" desc="ServletResponse">

		// TODO: flushBuffer?

		// TODO: reset?

		// TODO: resetBuffer?

		// TODO: setBufferSize?

		// TODO: setCharacterEncoding?

		// TODO: setContentLength?

		// TODO: setContentType?

		// TODO: setLocale?
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="HttpServletResponse">
		// TODO: addCookie?

		// TODO: headers

		/**
		 * @see  HttpServletResponse#sendError(int)
		 */
		public static class sendError {

			private sendError() {}

			/**
			 * Sends the provided HTTP status code.
			 *
			 * @see  HttpServletResponse#sendError(int)
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			private static class SendError implements Action {
				private final int sc;
				private SendError(int sc) {
					this.sc = sc;
				}
				@Override
				public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
					response.sendError(sc);
					return Result.TERMINATE;
				}
			}

			/**
			 * Sends the provided HTTP status code.
			 *
			 * @see  HttpServletResponse#sendError(int)
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action sendError(int sc) {
				switch(sc) {
					case HttpServletResponse.SC_CONTINUE : return CONTINUE;
					case HttpServletResponse.SC_SWITCHING_PROTOCOLS : return SWITCHING_PROTOCOLS;
					case HttpServletResponse.SC_OK : return OK;
					case HttpServletResponse.SC_CREATED : return CREATED;
					case HttpServletResponse.SC_ACCEPTED : return ACCEPTED;
					case HttpServletResponse.SC_NON_AUTHORITATIVE_INFORMATION : return NON_AUTHORITATIVE_INFORMATION;
					case HttpServletResponse.SC_NO_CONTENT : return NO_CONTENT;
					case HttpServletResponse.SC_RESET_CONTENT : return RESET_CONTENT;
					case HttpServletResponse.SC_PARTIAL_CONTENT : return PARTIAL_CONTENT;
					case HttpServletResponse.SC_MULTIPLE_CHOICES : return MULTIPLE_CHOICES;
					case HttpServletResponse.SC_MOVED_PERMANENTLY : return MOVED_PERMANENTLY;
					// Duplicate with SC_FOUND: case HttpServletResponse.SC_MOVED_TEMPORARILY : return MOVED_TEMPORARILY;
					case HttpServletResponse.SC_FOUND : return FOUND;
					case HttpServletResponse.SC_SEE_OTHER : return SEE_OTHER;
					case HttpServletResponse.SC_NOT_MODIFIED : return NOT_MODIFIED;
					case HttpServletResponse.SC_USE_PROXY : return USE_PROXY;
					case HttpServletResponse.SC_TEMPORARY_REDIRECT : return TEMPORARY_REDIRECT;
					case HttpServletResponse.SC_BAD_REQUEST : return BAD_REQUEST;
					case HttpServletResponse.SC_UNAUTHORIZED : return UNAUTHORIZED;
					case HttpServletResponse.SC_PAYMENT_REQUIRED : return PAYMENT_REQUIRED;
					case HttpServletResponse.SC_FORBIDDEN : return FORBIDDEN;
					case HttpServletResponse.SC_NOT_FOUND : return NOT_FOUND;
					case HttpServletResponse.SC_METHOD_NOT_ALLOWED : return METHOD_NOT_ALLOWED;
					case HttpServletResponse.SC_NOT_ACCEPTABLE : return NOT_ACCEPTABLE;
					case HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED : return PROXY_AUTHENTICATION_REQUIRED;
					case HttpServletResponse.SC_REQUEST_TIMEOUT : return REQUEST_TIMEOUT;
					case HttpServletResponse.SC_CONFLICT : return CONFLICT;
					case HttpServletResponse.SC_GONE : return GONE;
					case HttpServletResponse.SC_LENGTH_REQUIRED : return LENGTH_REQUIRED;
					case HttpServletResponse.SC_PRECONDITION_FAILED : return PRECONDITION_FAILED;
					case HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE : return REQUEST_ENTITY_TOO_LARGE;
					case HttpServletResponse.SC_REQUEST_URI_TOO_LONG : return REQUEST_URI_TOO_LONG;
					case HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE : return UNSUPPORTED_MEDIA_TYPE;
					case HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE : return REQUESTED_RANGE_NOT_SATISFIABLE;
					case HttpServletResponse.SC_EXPECTATION_FAILED : return EXPECTATION_FAILED;
					case HttpServletResponse.SC_INTERNAL_SERVER_ERROR : return INTERNAL_SERVER_ERROR;
					case HttpServletResponse.SC_NOT_IMPLEMENTED : return NOT_IMPLEMENTED;
					case HttpServletResponse.SC_BAD_GATEWAY : return BAD_GATEWAY;
					case HttpServletResponse.SC_SERVICE_UNAVAILABLE : return SERVICE_UNAVAILABLE;
					case HttpServletResponse.SC_GATEWAY_TIMEOUT : return GATEWAY_TIMEOUT;
					case HttpServletResponse.SC_HTTP_VERSION_NOT_SUPPORTED : return HTTP_VERSION_NOT_SUPPORTED;
					default : return new SendError(sc); // Other or future status codes
				}
			}

			/**
			 * Sends the provided HTTP status code and provided message.
			 *
			 * @see  HttpServletResponse#sendError(int, java.lang.String)
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action sendError(final int sc, final String message) {
				return new Action() {
					@Override
					public Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
						response.sendError(sc, message);
						return Result.TERMINATE;
					}
				};
			}

			/**
			 * @see  HttpServletResponse#SC_CONTINUE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action CONTINUE = new SendError(HttpServletResponse.SC_CONTINUE);

			/**
			 * @see  HttpServletResponse#SC_SWITCHING_PROTOCOLS
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action SWITCHING_PROTOCOLS = new SendError(HttpServletResponse.SC_SWITCHING_PROTOCOLS);

			/**
			 * @see  HttpServletResponse#SC_OK
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action OK = new SendError(HttpServletResponse.SC_OK);

			/**
			 * @see  HttpServletResponse#SC_CREATED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action CREATED = new SendError(HttpServletResponse.SC_CREATED);

			/**
			 * @see  HttpServletResponse#SC_ACCEPTED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action ACCEPTED = new SendError(HttpServletResponse.SC_ACCEPTED);

			/**
			 * @see  HttpServletResponse#SC_NON_AUTHORITATIVE_INFORMATION
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action NON_AUTHORITATIVE_INFORMATION = new SendError(HttpServletResponse.SC_NON_AUTHORITATIVE_INFORMATION);

			/**
			 * @see  HttpServletResponse#SC_NO_CONTENT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action NO_CONTENT = new SendError(HttpServletResponse.SC_NO_CONTENT);

			/**
			 * @see  HttpServletResponse#SC_RESET_CONTENT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action RESET_CONTENT = new SendError(HttpServletResponse.SC_RESET_CONTENT);

			/**
			 * @see  HttpServletResponse#SC_PARTIAL_CONTENT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action PARTIAL_CONTENT = new SendError(HttpServletResponse.SC_PARTIAL_CONTENT);

			/**
			 * @see  HttpServletResponse#SC_MULTIPLE_CHOICES
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action MULTIPLE_CHOICES = new SendError(HttpServletResponse.SC_MULTIPLE_CHOICES);

			/**
			 * @see  HttpServletResponse#SC_MOVED_PERMANENTLY
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action MOVED_PERMANENTLY = new SendError(HttpServletResponse.SC_MOVED_PERMANENTLY);

			/**
			 * @see  HttpServletResponse#SC_FOUND
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action FOUND = new SendError(HttpServletResponse.SC_FOUND);

			/**
			 * @see  HttpServletResponse#SC_MOVED_TEMPORARILY
			 *
			 * @return  {@link Result#TERMINATE} always
			 *
			 * @deprecated  Please use {@link #FOUND}
			 */
			@Deprecated
			public static final Action MOVED_TEMPORARILY = FOUND;

			/**
			 * @see  HttpServletResponse#SC_SEE_OTHER
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action SEE_OTHER = new SendError(HttpServletResponse.SC_SEE_OTHER);

			/**
			 * @see  HttpServletResponse#SC_NOT_MODIFIED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action NOT_MODIFIED = new SendError(HttpServletResponse.SC_NOT_MODIFIED);

			/**
			 * @see  HttpServletResponse#SC_USE_PROXY
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action USE_PROXY = new SendError(HttpServletResponse.SC_USE_PROXY);

			/**
			 * @see  HttpServletResponse#SC_TEMPORARY_REDIRECT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action TEMPORARY_REDIRECT = new SendError(HttpServletResponse.SC_TEMPORARY_REDIRECT);

			/**
			 * @see  HttpServletResponse#SC_BAD_REQUEST
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action BAD_REQUEST = new SendError(HttpServletResponse.SC_BAD_REQUEST);

			/**
			 * @see  HttpServletResponse#SC_UNAUTHORIZED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action UNAUTHORIZED = new SendError(HttpServletResponse.SC_UNAUTHORIZED);

			/**
			 * @see  HttpServletResponse#SC_PAYMENT_REQUIRED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action PAYMENT_REQUIRED = new SendError(HttpServletResponse.SC_PAYMENT_REQUIRED);

			/**
			 * @see  HttpServletResponse#SC_FORBIDDEN
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action FORBIDDEN = new SendError(HttpServletResponse.SC_FORBIDDEN);

			/**
			 * @see  HttpServletResponse#SC_NOT_FOUND
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action NOT_FOUND = new SendError(HttpServletResponse.SC_NOT_FOUND);

			/**
			 * @see  HttpServletResponse#SC_METHOD_NOT_ALLOWED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action METHOD_NOT_ALLOWED = new SendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);

			/**
			 * @see  HttpServletResponse#SC_NOT_ACCEPTABLE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action NOT_ACCEPTABLE = new SendError(HttpServletResponse.SC_NOT_ACCEPTABLE);

			/**
			 * @see  HttpServletResponse#SC_PROXY_AUTHENTICATION_REQUIRED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action PROXY_AUTHENTICATION_REQUIRED = new SendError(HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED);

			/**
			 * @see  HttpServletResponse#SC_REQUEST_TIMEOUT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action REQUEST_TIMEOUT = new SendError(HttpServletResponse.SC_REQUEST_TIMEOUT);

			/**
			 * @see  HttpServletResponse#SC_CONFLICT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action CONFLICT = new SendError(HttpServletResponse.SC_CONFLICT);

			/**
			 * @see  HttpServletResponse#SC_GONE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action GONE = new SendError(HttpServletResponse.SC_GONE);

			/**
			 * @see  HttpServletResponse#SC_LENGTH_REQUIRED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action LENGTH_REQUIRED = new SendError(HttpServletResponse.SC_LENGTH_REQUIRED);

			/**
			 * @see  HttpServletResponse#SC_PRECONDITION_FAILED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action PRECONDITION_FAILED = new SendError(HttpServletResponse.SC_PRECONDITION_FAILED);

			/**
			 * @see  HttpServletResponse#SC_REQUEST_ENTITY_TOO_LARGE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action REQUEST_ENTITY_TOO_LARGE = new SendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);

			/**
			 * @see  HttpServletResponse#SC_REQUEST_URI_TOO_LONG
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action REQUEST_URI_TOO_LONG = new SendError(HttpServletResponse.SC_REQUEST_URI_TOO_LONG);

			/**
			 * @see  HttpServletResponse#SC_UNSUPPORTED_MEDIA_TYPE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action UNSUPPORTED_MEDIA_TYPE = new SendError(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);

			/**
			 * @see  HttpServletResponse#SC_REQUESTED_RANGE_NOT_SATISFIABLE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action REQUESTED_RANGE_NOT_SATISFIABLE = new SendError(HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE);

			/**
			 * @see  HttpServletResponse#SC_EXPECTATION_FAILED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action EXPECTATION_FAILED = new SendError(HttpServletResponse.SC_EXPECTATION_FAILED);

			/**
			 * @see  HttpServletResponse#SC_INTERNAL_SERVER_ERROR
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action INTERNAL_SERVER_ERROR = new SendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

			/**
			 * @see  HttpServletResponse#SC_NOT_IMPLEMENTED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action NOT_IMPLEMENTED = new SendError(HttpServletResponse.SC_NOT_IMPLEMENTED);

			/**
			 * @see  HttpServletResponse#SC_BAD_GATEWAY
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action BAD_GATEWAY = new SendError(HttpServletResponse.SC_BAD_GATEWAY);

			/**
			 * @see  HttpServletResponse#SC_SERVICE_UNAVAILABLE
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action SERVICE_UNAVAILABLE = new SendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);

			/**
			 * @see  HttpServletResponse#SC_GATEWAY_TIMEOUT
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action GATEWAY_TIMEOUT = new SendError(HttpServletResponse.SC_GATEWAY_TIMEOUT);

			/**
			 * @see  HttpServletResponse#SC_HTTP_VERSION_NOT_SUPPORTED
			 *
			 * @return  {@link Result#TERMINATE} always
			 */
			public static final Action HTTP_VERSION_NOT_SUPPORTED = new SendError(HttpServletResponse.SC_HTTP_VERSION_NOT_SUPPORTED);
		}

		// TODO: sendRedirect

		// TODO: setStatus

		// </editor-fold>
	}
	// </editor-fold>

	// TODO: Cookies?

	// TODO: HttpSession?
}
