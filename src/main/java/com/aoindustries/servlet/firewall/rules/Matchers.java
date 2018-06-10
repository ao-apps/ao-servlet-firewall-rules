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

import com.aoindustries.net.pathspace.PathSpace;
import com.aoindustries.servlet.http.ServletUtil;
import com.aoindustries.util.WildcardPatternMatcher;
import com.aoindustries.validation.ValidationException;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A set of simple {@link Matcher} implementations.
 *
 * TODO: Don't like the idea of xml files declaring stuff away from where is used.
 * TODO: How to get the blocked-unless-enabled approach, and the servlet path spaces?
 * TODO: Set of annotations for servlets?  What would it mean?
 * TODO: Impossible to annotate JSP files, set of JSP tags?  Why there?
 * TODO: Is this blowing-up beyond what is needed by thinking too broadly of matchers and actions?
 *
 * TODO: Capture groups for regular expression-based matches, useful somehow in actions or further matchers?
 */
public class Matchers {

	private Matchers() {}

	// <editor-fold defaultstate="collapsed" desc="Logic">
	/**
	 * Matches none.
	 */
	public static final Matcher NONE = new Matcher() {
		@Override
		public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
			return false;
		}
	};

	/**
	 * Matches all.
	 */
	public static final Matcher ALL = new Matcher() {
		@Override
		public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
			return true;
		}
	};

	/**
	 * Negates a match.
	 */
	public static Matcher not(final Matcher matcher) {
		return new Matcher() {
			@Override
			public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
				return !matcher.matches(request, prefix, prefixPath, path);
			}
		};
	}

	/**
	 * Matches when all matchers match.
	 *
	 * @return  {@code true} when matchers is empty
	 */
	public static Matcher all(final Matcher ... matchers) {
		if(matchers.length == 0) return all();
		return new Matcher() {
			@Override
			public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
				for(Matcher matcher : matchers) {
					if(!matcher.matches(request, prefix, prefixPath, path)) return false;
				}
				return true;
			}
		};
	}

	/**
	 * Matches when all matchers match.
	 *
	 * @return  {@code true} when matchers is empty
	 */
	public static Matcher all(final Iterable<Matcher> matchers) {
		return new Matcher() {
			@Override
			public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
				for(Matcher matcher : matchers) {
					if(!matcher.matches(request, prefix, prefixPath, path)) return false;
				}
				return true;
			}
		};
	}

	/**
	 * Matches when any matchers match.
	 *
	 * @return  {@code false} when matchers is empty
	 */
	public static Matcher any(final Matcher ... matchers) {
		if(matchers.length == 0) return NONE;
		return new Matcher() {
			@Override
			public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
				for(Matcher matcher : matchers) {
					if(matcher.matches(request, prefix, prefixPath, path)) return true;
				}
				return false;
			}
		};
	}

	/**
	 * Matches when any matchers match.
	 *
	 * @return  {@code false} when matchers is empty
	 */
	public static Matcher any(final Iterable<Matcher> matchers) {
		return new Matcher() {
			@Override
			public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
				for(Matcher matcher : matchers) {
					if(matcher.matches(request, prefix, prefixPath, path)) return true;
				}
				return false;
			}
		};
	}
	// </editor-fold>

	// TODO: Filter name and init parameters from ao-servlet-firewall-filter?
	// TODO: FilterRegistration?
	// TODO: Registration?
	// TODO: Servlet/HttpServlet/ServletConfig/ServletRegistration anything useful at filter processing stage?

	// TODO: RequestDispatcher (and all associated constants)?

	// <editor-fold defaultstate="collapsed" desc="ServletContext">
	/**
	 * @see  javax.servlet.ServletContext
	 */
	public static class ServletContext {

		private ServletContext() {}

		// TODO: orderedLibs, tempDir (from constants?)

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: getContextPath()?

		// TODO: Default and Effective SessionTrackingModes?

		// TODO: EffectiveMajorVersion / EffectiveMinorVersion / MajorVersion, MinorVersion?

		// TODO: InitParameters

		// TODO: jsp-config

		// TODO: hasNamedDispatcher?

		// TODO: getRealPath? (has realPath)?

		// TODO: hasRequestDispatcher?

		// TODO: Resources?

		// TODO: ServerInfo?

		// TODO: ServletContextName?

		// TODO: Servlet registrations?

		// TODO: SessionCookieConfig?

		// TODO: log as non-terminal action?
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="ServletRequest">
	/**
	 * @see  javax.servlet.ServletRequest
	 */
	public static class ServletRequest {

		private ServletRequest() {}

		// TODO: AsyncContext (and all associated constants)?

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: getCharacterEncoding?

		// TODO: getContentLength?

		// TODO: getContentType?

		// <editor-fold defaultstate="collapsed" desc="DispatcherType">
		/**
		 * @see  ServletRequest#getDispatcherType()
		 */
		public static class DispatcherType {

			private DispatcherType() {}

			/**
			 * Matches {@link javax.servlet.DispatcherType#FORWARD}
			 */
			public static final Matcher FORWARD = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return request.getDispatcherType() == javax.servlet.DispatcherType.FORWARD;
				}
			};

			/**
			 * Matches {@link javax.servlet.DispatcherType#INCLUDE}
			 */
			public static final Matcher INCLUDE = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return request.getDispatcherType() == javax.servlet.DispatcherType.INCLUDE;
				}
			};

			/**
			 * Matches {@link javax.servlet.DispatcherType#REQUEST}
			 */
			public static final Matcher REQUEST = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return request.getDispatcherType() == javax.servlet.DispatcherType.REQUEST;
				}
			};

			/**
			 * Matches {@link javax.servlet.DispatcherType#ASYNC}
			 */
			public static final Matcher ASYNC = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return request.getDispatcherType() == javax.servlet.DispatcherType.ASYNC;
				}
			};

			/**
			 * Matches {@link javax.servlet.DispatcherType#ERROR}
			 */
			public static final Matcher ERROR = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return request.getDispatcherType() == javax.servlet.DispatcherType.ERROR;
				}
			};

			/**
			 * Matches any of a given iterable of {@link javax.servlet.DispatcherType}
			 */
			public static Matcher in(final Iterable<javax.servlet.DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						javax.servlet.DispatcherType type = request.getDispatcherType();
						for(javax.servlet.DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) return true;
						}
						return false;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}
			 */
			public static Matcher in(final EnumSet<javax.servlet.DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return dispatcherTypes.contains(request.getDispatcherType());
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}
			 */
			public static Matcher in(javax.servlet.DispatcherType ... dispatcherTypes) {
				if(dispatcherTypes.length == 0) return NONE;
				return in(EnumSet.of(dispatcherTypes[0], dispatcherTypes));
			}
		}
		// </editor-fold>

		// TODO: getLocalAddr/getLocalName/getLocalPort

		// TODO: getLocale(s)

		// TODO: Parameters

		// TODO: getProtocol

		// TODO: getRemoteAddr/getRemoteHost/getRemotePort

		// TODO: getRequestDispatcher?

		// TODO: getScheme

		// TODO: getServerName/getServerPort

		// TODO: isAsyncStarted/Supported?

		// TODO: isSecure?
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="HttpServletRequest">
	/**
	 * @see  javax.servlet.http.HttpServletRequest
	 */
	public static class HttpServletRequest {

		private HttpServletRequest() {}

		// <editor-fold defaultstate="collapsed" desc="AuthType">
		/**
		 * @see  javax.servlet.http.HttpServletRequest#getAuthType()
		 */
		public static class AuthType {

			private AuthType() {}

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getAuthType()} of {@link javax.servlet.http.HttpServletRequest#BASIC_AUTH}.
			 */
			public static final Matcher BASIC = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return javax.servlet.http.HttpServletRequest.BASIC_AUTH.equals(request.getAuthType());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getAuthType()} of {@link javax.servlet.http.HttpServletRequest#CLIENT_CERT_AUTH}.
			 */
			public static final Matcher CLIENT_CERT = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return javax.servlet.http.HttpServletRequest.CLIENT_CERT_AUTH.equals(request.getAuthType());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getAuthType()} of {@link javax.servlet.http.HttpServletRequest#DIGEST_AUTH}.
			 */
			public static final Matcher DIGEST = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return javax.servlet.http.HttpServletRequest.DIGEST_AUTH.equals(request.getAuthType());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getAuthType()} of {@link javax.servlet.http.HttpServletRequest#FORM_AUTH}.
			 */
			public static final Matcher FORM = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return javax.servlet.http.HttpServletRequest.FORM_AUTH.equals(request.getAuthType());
				}
			};

			/**
			 * Matches any of a given iterable of {@link javax.servlet.http.HttpServletRequest#getAuthType()}, case-insensitive.
			 */
			public static Matcher in(final Iterable<String> authTypes) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						String type = request.getAuthType();
						for(String authType : authTypes) {
							if(type.equalsIgnoreCase(authType)) return true;
						}
						return false;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.http.HttpServletRequest#getAuthType()}, uppercase matched in
			 * {@link Locale#ROOT}.
			 *
			 * @see  Collection#contains(java.lang.Object)
			 */
			public static Matcher in(final Collection<String> authTypes) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return authTypes.contains(request.getAuthType().toLowerCase(Locale.ROOT));
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.http.HttpServletRequest#getAuthType()}, case-insensitive.
			 */
			public static Matcher in(final String ... authTypes) {
				if(authTypes.length == 0) return NONE;
				Set<String> set = new LinkedHashSet<String>(authTypes.length*4/3+1);
				for(String authType : authTypes) {
					set.add(authType.toUpperCase(Locale.ROOT));
				}
				return in(set);
			}
		}
		// </editor-fold>

		// TODO: getContextPath?

		// TODO: Cookies?

		// TODO: Headers?

		// <editor-fold defaultstate="collapsed" desc="Method">
		/**
		 * @see  javax.servlet.http.HttpServletRequest#getMethod()
		 */
		public static class Method {

			private Method() {}

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_DELETE}.
			 */
			public static final Matcher DELETE = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_DELETE.equals(request.getMethod());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_HEAD}.
			 */
			public static final Matcher HEAD = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_HEAD.equals(request.getMethod());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_GET}.
			 */
			public static final Matcher GET = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_GET.equals(request.getMethod());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_OPTIONS}.
			 */
			public static final Matcher OPTIONS = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_OPTIONS.equals(request.getMethod());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_POST}.
			 */
			public static final Matcher POST = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_POST.equals(request.getMethod());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_PUT}.
			 */
			public static final Matcher PUT = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_PUT.equals(request.getMethod());
				}
			};

			/**
			 * Matches {@link javax.servlet.http.HttpServletRequest#getMethod()} of {@link ServletUtil#METHOD_TRACE}.
			 */
			public static final Matcher TRACE = new Matcher() {
				@Override
				public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					return ServletUtil.METHOD_TRACE.equals(request.getMethod());
				}
			};

			/**
			 * Matches any of a given iterable of {@link javax.servlet.http.HttpServletRequest#getMethod()}, case-insensitive.
			 */
			public static Matcher in(final Iterable<String> requestMethods) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						String method = request.getMethod();
						for(String requestMethod : requestMethods) {
							if(method.equalsIgnoreCase(requestMethod)) return true;
						}
						return false;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.http.HttpServletRequest#getMethod()}, uppercase matched in
			 * {@link Locale#ROOT}.
			 *
			 * @see  Collection#contains(java.lang.Object)
			 */
			public static Matcher in(final Collection<String> requestMethods) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return requestMethods.contains(request.getMethod().toLowerCase(Locale.ROOT));
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.http.HttpServletRequest#getMethod()}, case-insensitive.
			 */
			public static Matcher in(final String ... requestMethods) {
				if(requestMethods.length == 0) return NONE;
				Set<String> set = new LinkedHashSet<String>(requestMethods.length*4/3+1);
				for(String requestMethod : requestMethods) {
					set.add(requestMethod.toUpperCase(Locale.ROOT));
				}
				return in(set);
			}
		}
		// </editor-fold>

		// TODO: Part (to block/require file uploads) - See ao-servlet-filters for helpful upload handler

		// TODO: pathInfo?

		// TODO: pathTranslated?

		// TODO: queryString?

		// TODO: RemoteUser

		// TODO: RequestURI?

		// TODO: RequestURL?

		// TODO: getServletPath? (this is provided already)

		// TODO: Session stuff (with potential to set in non-terminating action)?

		// TODO: UserPrincipal

		// TODO: isUserInRole

		// TODO: For actions: logout()?
	}
	// </editor-fold>

	// TODO: Cookies?

	// TODO: HttpSession?

	// TODO: javax.servlet.descriptor package?

	// TODO: AO-include/forward args?

	// <editor-fold defaultstate="collapsed" desc="PathMatch">
	/**
	 * @see  PathSpace.PathMatch
	 */
	public static class PathMatch {

		private PathMatch() {}

		// <editor-fold defaultstate="collapsed" desc="prefix">
		/**
		 * @see  PathSpace.PathMatch#getPrefix()
		 */
		public static class Prefix {

			private Prefix() {}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive
			 *
			 * @return  {@code true} when startsWith is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String startsWith) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().startsWith(startsWith);
					}
				};
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive
			 *
			 * @return  {@code true} when endsWith is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String endsWith) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().endsWith(endsWith);
					}
				};
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive
			 *
			 * @return  {@code true} when contains is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence contains) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().contains(contains);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.pathspace.Prefix target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 * @see  #equals(com.aoindustries.net.pathspace.Prefix)
			 */
			public static Matcher equals(final String target) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target));
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string buffer, case-sensitive
			 *
			 * @see  String#contentEquals(java.lang.StringBuffer)
			 */
			public static Matcher equals(final StringBuffer target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			* Matches when a request prefix matches a given regular expression.
			*
			* @see  Pattern#compile(java.lang.String)
			* @see  Pattern#compile(java.lang.String, int)
			*/
		   public static Matcher matches(final Pattern pattern) {
			   return new Matcher() {
				   @Override
				   public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					   return pattern.matcher(prefix.toString()).matches();
				   }
			   };
		   }

		   /**
			* Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			* <p>
			* {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			* especially in suffix matching.
			* </p>
			* <p>
			* TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger aocode-public project.
			* </p>
			*
			* @see  WildcardPatternMatcher#compile(java.lang.String)
			* 
			*/
		   public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
			   return new Matcher() {
				   @Override
				   public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					   return wildcardPattern.isMatch(prefix.toString());
				   }
			   };
		   }
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="prefixPath">
		/**
		 * @see  PathSpace.PathMatch#getPrefixPath()
		 */
		public static class PrefixPath {

			private PrefixPath() {}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive
			 *
			 * @return  {@code true} when startsWith is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String startsWith) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().startsWith(startsWith);
					}
				};
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive
			 *
			 * @return  {@code true} when endsWith is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String endsWith) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().endsWith(endsWith);
					}
				};
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive
			 *
			 * @return  {@code true} when contains is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence contains) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().contains(contains);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.Path target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 * @see  #equals(com.aoindustries.net.Path)
			 */
			public static Matcher equals(final String target) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string buffer, case-sensitive
			 *
			 * @see  String#contentEquals(java.lang.StringBuffer)
			 */
			public static Matcher equals(final StringBuffer target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return pattern.matcher(prefixPath.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 * <p>
			 * TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger aocode-public project.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 * 
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return wildcardPattern.isMatch(prefixPath.toString());
					}
				};
			}
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="path">
		/**
		 * @see  PathSpace.PathMatch#getPath()
		 */
		public static class Path {

			private Path() {}

			/**
			 * Matches when a request path starts with a given string, case-sensitive
			 *
			 * @return  {@code true} when startsWith is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String startsWith) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().startsWith(startsWith);
					}
				};
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive
			 *
			 * @return  {@code true} when endsWith is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String endsWith) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().endsWith(endsWith);
					}
				};
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive
			 *
			 * @return  {@code true} when contains is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence contains) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().contains(contains);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.Path target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.equals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 * @see  #equals(com.aoindustries.net.Path)
			 */
			public static Matcher equals(final String target) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string buffer, case-sensitive
			 *
			 * @see  String#contentEquals(java.lang.StringBuffer)
			 */
			public static Matcher equals(final StringBuffer target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return pattern.matcher(path.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 * <p>
			 * TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger aocode-public project.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 * 
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
				return new Matcher() {
					@Override
					public boolean matches(javax.servlet.http.HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return wildcardPattern.isMatch(path.toString());
					}
				};
			}
		}

		// TODO: String.regionMatches?

		// TODO: More case-insensitive of the above?

		// TODO: CompareTo for before/after/ <=, >=?

		// </editor-fold>
	}
	// </editor-fold>
}
