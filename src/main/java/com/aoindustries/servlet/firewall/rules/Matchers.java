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
import com.aoindustries.servlet.firewall.rules.Rule.Result;
import com.aoindustries.servlet.http.ServletUtil;
import com.aoindustries.util.AoCollections;
import com.aoindustries.util.WildcardPatternMatcher;
import com.aoindustries.validation.ValidationException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.regex.Pattern;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
 *
 * TODO: Could/should CSRF be built into the firewall? Or is that a separate concept?
 *
 * TODO: FirewallContext that should be used to invoke all matchers and rules.  This would provide the hooks for tools like "TRACE" useful in debugging/development.
 *
 * @implNote  Defensive copying of collections is not performed, intentionally allowing callers to provided mutable collections.
 *            Although this should be used sparingly, it may be appropriate for rules that call-out to other APIs,
 *            such as ACLs inside of a database.
 *
 * @implNote  Arrays are not necessarily defensively copied, but the elements of the arrays might also be extracted.  Mutation of
 *            arrays is not supported.
 */
public class Matchers {

	private Matchers() {}

	// <editor-fold defaultstate="collapsed" desc="Logic">
	/**
	 * Matches none.
	 *
	 * @return  {@link Result#NO_MATCH} always
	 *
	 * @see  #any(java.lang.Iterable)
	 * @see  #any(com.aoindustries.servlet.firewall.rules.Rule...)
	 */
	public static final Matcher none = new Matcher() {
		@Override
		public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
			return Result.NO_MATCH;
		}
	};

	/**
	 * Matches all.
	 *
	 * @return  {@link Result#MATCH} always
	 */
	public static final Matcher all = new Matcher() {
		@Override
		public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
			return Result.MATCH;
		}
	};

	/**
	 * Matches when all matchers match.
	 * Stops processing rules (both matchers and actions) when the first matcher does not match.
	 * Performs any actions while processing rules, up to the point stopped on first non-matching matcher.
	 *
	 * @return  {@link Result#MATCH} when matchers is empty
	 */
	public static Matcher all(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
				for(Rule rule : rules) {
					Result result = rule.perform(request, response, chain);
					switch(result) {
						case TERMINATE :
							return Result.TERMINATE;
						case CONTINUE :
							assert rule instanceof Action;
							break;
						case NO_MATCH :
							assert rule instanceof Matcher;
							return Result.NO_MATCH;
						case MATCH :
							assert rule instanceof Matcher;
							break;
						default :
							throw new AssertionError();
					}
				}
				return Result.MATCH;
			}
		};
	}

	public static Matcher all(Rule ... rules) {
		if(rules.length == 0) return all;
		return all(Arrays.asList(rules));
	}

	/**
	 * Matches when any matchers match.
	 * Stops processing matchers once the first match is found.
	 * Begins processing actions once the first match is found.
	 *
	 * @return  {@link Result#NO_MATCH} when matchers is empty
	 *
	 * @see  #none
	 */
	public static Matcher any(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
				boolean matched = false;
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						if(!matched) {
							Result result = rule.perform(request, response, chain);
							switch(result) {
								case TERMINATE :
									return Result.TERMINATE;
								case MATCH :
									matched = true;
									break;
								case NO_MATCH :
									// Continue lookning for first match
									break;
								default :
									throw new AssertionError("Invalid result from Matcher.perform: " + result);
							}
						}
					} else {
						assert rule instanceof Action;
						if(matched) {
							Result result = rule.perform(request, response, chain);
							switch(result) {
								case TERMINATE :
									return Result.TERMINATE;
								case CONTINUE :
									// Continue with any additional actions
									break;
								default :
									throw new AssertionError("Invalid result from Action.perform: " + result);
							}
						}
					}
				}
				return matched ? Result.MATCH : Result.NO_MATCH;
			}
		};
	}

	/**
	 * @see  #none
	 */
	public static Matcher any(Rule ... rules) {
		if(rules.length == 0) return none;
		return any(Arrays.asList(rules));
	}

	/**
	 * Negates a match.
	 *
	 * TODO: What would it mean to handle multiple rules?  Or best used with "not/any" "not/all"?
	 * TODO: Should the negation be passed on to them regarding their invocation of any nested actions?
	 */
	public static Matcher not(final Matcher matcher) {
		return new Matcher() {
			@Override
			public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
				Result result = matcher.perform(request, response, chain);
				if(result == Result.TERMINATE) return Result.TERMINATE;
				if(result == Result.MATCH) return Result.NO_MATCH;
				if(result == Result.NO_MATCH) return Result.MATCH;
				throw new AssertionError("Invalid result from Matcher.perform: " + result);
			}
		};
	}
	// </editor-fold>

	// TODO: Registration?
	// TODO: Servlet/HttpServlet/ServletConfig/ServletRegistration anything useful at filter processing stage?

	// TODO: RequestDispatcher (and all associated constants)?

	// <editor-fold defaultstate="collapsed" desc="Context">
	/**
	 * @see  ServletContext
	 */
	public static class Context {

		private Context() {}

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

	// TODO: Filter name and init parameters from ao-servlet-firewall-filter?
	// TODO: FilterRegistration?

	// <editor-fold defaultstate="collapsed" desc="Request">
	/**
	 * @see  ServletRequest
	 * @see  HttpServletRequest
	 */
	public static class Request {

		private Request() {}

		// <editor-fold defaultstate="collapsed" desc="ServletRequest">

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

			private static class Is implements Matcher {
				private final javax.servlet.DispatcherType dispatcherType;
				private Is(javax.servlet.DispatcherType dispatcherType) {
					this.dispatcherType = dispatcherType;
				}
				@Override
				public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
					return request.getDispatcherType() == dispatcherType
						? Result.MATCH
						: Result.NO_MATCH;
				}
			}

			/**
			 * Matches one given {@link javax.servlet.DispatcherType}.
			 */
			public static Matcher is(javax.servlet.DispatcherType dispatcherType) {
				switch(dispatcherType) {
					case FORWARD : return isForward;
					case INCLUDE : return isInclude;
					case REQUEST : return isRequest;
					case ASYNC   : return isAsync;
					case ERROR   : return isError;
					default      : return new Is(dispatcherType); // For any future dispatcher type
				}
			}

			/**
			 * Matches one given {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher is(final javax.servlet.DispatcherType dispatcherType, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						if(request.getDispatcherType() == dispatcherType) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches one given {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher is(javax.servlet.DispatcherType dispatcherType, Rule ... rules) {
				if(rules.length == 0) return is(dispatcherType);
				return is(dispatcherType, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given iterable of {@link javax.servlet.DispatcherType}.
			 */
			public static Matcher in(final Iterable<? extends javax.servlet.DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
						javax.servlet.DispatcherType type = request.getDispatcherType();
						for(javax.servlet.DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) return Result.MATCH;
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}.
			 */
			public static Matcher in(final EnumSet<? extends javax.servlet.DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
						return dispatcherTypes.contains(request.getDispatcherType())
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}.
			 */
			public static Matcher in(javax.servlet.DispatcherType ... dispatcherTypes) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0]);
				return in(EnumSet.of(dispatcherTypes[0], dispatcherTypes));
			}

			/**
			 * Matches any of a given iterable of {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(final Iterable<? extends javax.servlet.DispatcherType> dispatcherTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						javax.servlet.DispatcherType type = request.getDispatcherType();
						for(javax.servlet.DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) {
								for(Rule rule : rules) {
									Result result = rule.perform(request, response, chain);
									if(result == Result.TERMINATE) return Result.TERMINATE;
								}
								return Result.MATCH;
							}
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(final EnumSet<? extends javax.servlet.DispatcherType> dispatcherTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						if(dispatcherTypes.contains(request.getDispatcherType())) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(javax.servlet.DispatcherType[] dispatcherTypes, final Iterable<? extends Rule> rules) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0], rules);
				return in(EnumSet.of(dispatcherTypes[0], dispatcherTypes), rules);
			}

			/**
			 * Matches any of a given iterable of {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(Iterable<? extends javax.servlet.DispatcherType> dispatcherTypes, Rule ... rules) {
				if(rules.length == 0) return in(dispatcherTypes);
				return in(dispatcherTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(EnumSet<? extends javax.servlet.DispatcherType> dispatcherTypes, Rule ... rules) {
				if(rules.length == 0) return in(dispatcherTypes);
				return in(dispatcherTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link javax.servlet.DispatcherType}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(javax.servlet.DispatcherType[] dispatcherTypes, Rule ... rules) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0], rules);
				if(rules.length == 0) return in(dispatcherTypes);
				return in(dispatcherTypes, Arrays.asList(rules));
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#FORWARD}.
			 */
			public static final Matcher isForward = new Is(javax.servlet.DispatcherType.FORWARD);

			/**
			 * Matches {@link javax.servlet.DispatcherType#FORWARD}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isForward(final Iterable<? extends Rule> rules) {
				return is(javax.servlet.DispatcherType.FORWARD, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#FORWARD}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isForward(Rule ... rules) {
				return is(javax.servlet.DispatcherType.FORWARD, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#INCLUDE}.
			 */
			public static final Matcher isInclude = new Is(javax.servlet.DispatcherType.INCLUDE);

			/**
			 * Matches {@link javax.servlet.DispatcherType#INCLUDE}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isInclude(final Iterable<? extends Rule> rules) {
				return is(javax.servlet.DispatcherType.INCLUDE, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#INCLUDE}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isInclude(Rule ... rules) {
				return is(javax.servlet.DispatcherType.INCLUDE, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#REQUEST}.
			 */
			public static final Matcher isRequest = new Is(javax.servlet.DispatcherType.REQUEST);

			/**
			 * Matches {@link javax.servlet.DispatcherType#REQUEST}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isRequest(final Iterable<? extends Rule> rules) {
				return is(javax.servlet.DispatcherType.REQUEST, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#REQUEST}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isRequest(Rule ... rules) {
				return is(javax.servlet.DispatcherType.REQUEST, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#ASYNC}.
			 */
			public static final Matcher isAsync = new Is(javax.servlet.DispatcherType.ASYNC);

			/**
			 * Matches {@link javax.servlet.DispatcherType#ASYNC}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isAsync(final Iterable<? extends Rule> rules) {
				return is(javax.servlet.DispatcherType.ASYNC, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#ASYNC}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isAsync(Rule ... rules) {
				return is(javax.servlet.DispatcherType.ASYNC, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#ERROR}.
			 */
			public static final Matcher isError = new Is(javax.servlet.DispatcherType.ERROR);

			/**
			 * Matches {@link javax.servlet.DispatcherType#ERROR}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isError(final Iterable<? extends Rule> rules) {
				return is(javax.servlet.DispatcherType.ERROR, rules);
			}

			/**
			 * Matches {@link javax.servlet.DispatcherType#ERROR}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isError(Rule ... rules) {
				return is(javax.servlet.DispatcherType.ERROR, rules);
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

		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="HttpServletRequest">

		// <editor-fold defaultstate="collapsed" desc="AuthType">
		/**
		 * TODO: Support nulls?
		 *
		 * @see  HttpServletRequest#getAuthType()
		 */
		public static class AuthType {

			private AuthType() {}

			private static class Is implements Matcher {
				private final String authType;
				private Is(String authType) {
					this.authType = authType;
				}
				@Override
				public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
					String type = request.getAuthType();
					return type != null && type.equals(authType)
						? Result.MATCH
						: Result.NO_MATCH;
				}
			}

			/**
			 * Matches one given {@link HttpServletRequest#getAuthType()}.
			 */
			public static Matcher is(String authType) {
				if(HttpServletRequest.BASIC_AUTH.equals(authType)) return isBasic;
				if(HttpServletRequest.FORM_AUTH.equals(authType)) return isForm;
				if(HttpServletRequest.CLIENT_CERT_AUTH.equals(authType)) return isClientCert;
				if(HttpServletRequest.DIGEST_AUTH.equals(authType)) return isDigest;
				return new Is(authType); // For container-specific or any future auth types
			}

			/**
			 * Matches one given {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher is(final String authType, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						String type = request.getAuthType();
						if(type != null && type.equals(authType)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches one given {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher is(String authType, Rule ... rules) {
				if(rules.length == 0) return is(authType);
				return is(authType, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 */
			public static Matcher in(final Iterable<? extends String> authTypes) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
						String type = request.getAuthType();
						if(type != null) {
							for(String authType : authTypes) {
								if(type.equals(authType)) return Result.MATCH;
							}
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 */
			public static Matcher in(final Collection<? extends String> authTypes) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
						String type = request.getAuthType();
						return type != null && authTypes.contains(type)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 */
			public static Matcher in(String ... authTypes) {
				if(authTypes.length == 0) return none;
				if(authTypes.length == 1) return is(authTypes[0]);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(authTypes)));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(final Iterable<? extends String> authTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						String type = request.getAuthType();
						if(type != null) {
							for(String authType : authTypes) {
								if(type.equals(authType)) {
									for(Rule rule : rules) {
										Result result = rule.perform(request, response, chain);
										if(result == Result.TERMINATE) return Result.TERMINATE;
									}
									return Result.MATCH;
								}
							}
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(final Collection<? extends String> authTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						String type = request.getAuthType();
						if(type != null && authTypes.contains(type)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(String[] authTypes, final Iterable<? extends Rule> rules) {
				if(authTypes.length == 0) return none;
				if(authTypes.length == 1) return is(authTypes[0], rules);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(authTypes)), rules);
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(Iterable<? extends String> authTypes, Rule ... rules) {
				if(rules.length == 0) return in(authTypes);
				return in(authTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(Collection<? extends String> authTypes, Rule ... rules) {
				if(rules.length == 0) return in(authTypes);
				return in(authTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(String[] authTypes, Rule ... rules) {
				if(authTypes.length == 0) return none;
				if(authTypes.length == 1) return is(authTypes[0], rules);
				if(rules.length == 0) return in(authTypes);
				return in(authTypes, Arrays.asList(rules));
			}

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 */
			public static final Matcher isBasic = new Is(HttpServletRequest.BASIC_AUTH);

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isBasic(final Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.BASIC_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isBasic(Rule ... rules) {
				return is(HttpServletRequest.BASIC_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 */
			public static final Matcher isForm = new Is(HttpServletRequest.FORM_AUTH);

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isForm(final Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.FORM_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isForm(Rule ... rules) {
				return is(HttpServletRequest.FORM_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 */
			public static final Matcher isClientCert = new Is(HttpServletRequest.CLIENT_CERT_AUTH);

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isClientCert(final Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.CLIENT_CERT_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isClientCert(Rule ... rules) {
				return is(HttpServletRequest.CLIENT_CERT_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 */
			public static final Matcher isDigest = new Is(HttpServletRequest.DIGEST_AUTH);

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isDigest(final Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.DIGEST_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isDigest(Rule ... rules) {
				return is(HttpServletRequest.DIGEST_AUTH, rules);
			}
		}
		// </editor-fold>

		// TODO: getContextPath?

		// TODO: Cookies?

		// TODO: Headers?

		// <editor-fold defaultstate="collapsed" desc="Method">
		/**
		 * @see  HttpServletRequest#getMethod()
		 */
		public static class Method {

			private Method() {}

			private static class Is implements Matcher {
				private final String method;
				private Is(String method) {
					this.method = method;
				}
				@Override
				public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
					return request.getMethod().equals(method)
						? Result.MATCH
						: Result.NO_MATCH;
				}
			}

			/**
			 * Matches one given {@link HttpServletRequest#getMethod()}.
			 */
			public static Matcher is(String method) {
				if(ServletUtil.METHOD_DELETE .equals(method)) return isDelete;
				if(ServletUtil.METHOD_HEAD   .equals(method)) return isHead;
				if(ServletUtil.METHOD_GET    .equals(method)) return isGet;
				if(ServletUtil.METHOD_OPTIONS.equals(method)) return isOptions;
				if(ServletUtil.METHOD_POST   .equals(method)) return isPost;
				if(ServletUtil.METHOD_PUT    .equals(method)) return isPut;
				if(ServletUtil.METHOD_TRACE  .equals(method)) return isTrace;
				return new Is(method); // For any other methods
			}

			/**
			 * Matches one given {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher is(final String method, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						if(request.getMethod().equals(method)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches one given {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher is(String method, Rule ... rules) {
				if(rules.length == 0) return is(method);
				return is(method, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 */
			public static Matcher in(final Iterable<? extends String> methods) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
						String m = request.getMethod();
						for(String method : methods) {
							if(m.equals(method)) return Result.MATCH;
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 */
			public static Matcher in(final Collection<? extends String> methods) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
						return methods.contains(request.getMethod())
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 */
			public static Matcher in(String ... methods) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0]);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(methods)));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(final Iterable<? extends String> methods, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						String m = request.getMethod();
						for(String method : methods) {
							if(m.equals(method)) {
								for(Rule rule : rules) {
									Result result = rule.perform(request, response, chain);
									if(result == Result.TERMINATE) return Result.TERMINATE;
								}
								return Result.MATCH;
							}
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(final Collection<? extends String> methods, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
						if(methods.contains(request.getMethod())) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(String[] methods, final Iterable<? extends Rule> rules) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0], rules);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(methods)), rules);
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(Iterable<? extends String> methods, Rule ... rules) {
				if(rules.length == 0) return in(methods);
				return in(methods, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(Collection<? extends String> methods, Rule ... rules) {
				if(rules.length == 0) return in(methods);
				return in(methods, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher in(String[] methods, Rule ... rules) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0], rules);
				if(rules.length == 0) return in(methods);
				return in(methods, Arrays.asList(rules));
			}

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 */
			public static final Matcher isDelete = new Is(ServletUtil.METHOD_DELETE);

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isDelete(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_DELETE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isDelete(Rule ... rules) {
				return is(ServletUtil.METHOD_DELETE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 */
			public static final Matcher isHead = new Is(ServletUtil.METHOD_HEAD);

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isHead(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_HEAD, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isHead(Rule ... rules) {
				return is(ServletUtil.METHOD_HEAD, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 */
			public static final Matcher isGet = new Is(ServletUtil.METHOD_GET);

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isGet(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_GET, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isGet(Rule ... rules) {
				return is(ServletUtil.METHOD_GET, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 */
			public static final Matcher isOptions = new Is(ServletUtil.METHOD_OPTIONS);

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isOptions(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_OPTIONS, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isOptions(Rule ... rules) {
				return is(ServletUtil.METHOD_OPTIONS, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 */
			public static final Matcher isPost = new Is(ServletUtil.METHOD_POST);

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isPost(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_POST, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isPost(Rule ... rules) {
				return is(ServletUtil.METHOD_POST, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 */
			public static final Matcher isPut = new Is(ServletUtil.METHOD_PUT);

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isPut(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_PUT, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isPut(Rule ... rules) {
				return is(ServletUtil.METHOD_PUT, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 */
			public static final Matcher isTrace = new Is(ServletUtil.METHOD_TRACE);

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isTrace(final Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_TRACE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 * Invokes the provided rules only when matched.
			 */
			public static Matcher isTrace(Rule ... rules) {
				return is(ServletUtil.METHOD_TRACE, rules);
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

		// </editor-fold>
	}
	// </editor-fold>

	// TODO: Cookies?

	// TODO: HttpSession?

	// TODO: javax.servlet.descriptor package?

	// TODO: AO-include/forward args?

	// <editor-fold defaultstate="collapsed" desc="PathMatch">
	/**
	 * TODO: Move to own package or to path-space or servlet-space package?
	 *
	 * @see  PathSpace.PathMatch
	 */
	public static class PathMatch {

		/**
		 * The request key that holds the current PathMatch.
		 */
		private static final String PATH_MATCH_REQUEST_KEY = PathMatch.class.getName();

		/**
		 * Gets the {@link PathSpace.PathMatch} for the current servlet space.
		 *
		 * @throws ServletException when no {@link PathSpace.PathMatch} set.
		 */
		private static PathSpace.PathMatch<?> getPathMatch(ServletRequest request) throws ServletException {
			PathSpace.PathMatch<?> pathMatch = (PathSpace.PathMatch<?>)request.getAttribute(PATH_MATCH_REQUEST_KEY);
			if(pathMatch == null) throw new ServletException("PathMatch not set on request");
			return pathMatch;
		}

		private abstract static class PathMatchMatcher implements Matcher {
			@Override
			final public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
				PathSpace.PathMatch<?> pathMatch = getPathMatch(request);
				return perform(
					request,
					response,
					chain,
					pathMatch.getPrefix(),
					pathMatch.getPrefixPath(),
					pathMatch.getPath()
				);
			}

			/**
			 * @param  prefix  See {@link PathSpace.PathMatch#getPrefix()}
			 * @param  prefixPath  See {@link PathSpace.PathMatch#getPrefixPath()}
			 * @param  path  See {@link PathSpace.PathMatch#getPath()}
			 *
			 * @see  #perform(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
			 */
			abstract protected Result perform(
				HttpServletRequest request,
				HttpServletResponse response,
				FilterChain chain,
				com.aoindustries.net.pathspace.Prefix prefix,
				com.aoindustries.net.Path prefixPath,
				com.aoindustries.net.Path path
			) throws IOException, ServletException;
		}

		private PathMatch() {}

		// <editor-fold defaultstate="collapsed" desc="prefix">
		/**
		 * @see  PathSpace.PathMatch#getPrefix()
		 */
		public static class prefix {

			private prefix() {}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return _prefix.toString().startsWith(prefix)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(_prefix.toString().startsWith(prefix)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().endsWith(suffix)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(_prefix.toString().endsWith(suffix)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().contains(substring)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefix.toString().contains(substring)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.pathspace.Prefix target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.equals(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.pathspace.Prefix target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefix.equals(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(com.aoindustries.net.pathspace.Prefix target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target), rules);
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target), rules);
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().contentEquals(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						// TODO: Put this into the parent class, with a "rules" variant and a matches method - others too
						if(prefix.toString().contentEquals(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefix.toString().equalsIgnoreCase(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefix.toString().equalsIgnoreCase(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
					   return pattern.matcher(prefix.toString()).matches()
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(pattern.matcher(prefix.toString()).matches()) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
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
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return wildcardPattern.isMatch(prefix.toString())
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			 * Invokes the provided rules only when matched.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(wildcardPattern.isMatch(prefix.toString())) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			 * Invokes the provided rules only when matched.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="prefixPath">
		/**
		 * @see  PathSpace.PathMatch#getPrefixPath()
		 */
		public static class prefixPath {

			private prefixPath() {}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().startsWith(prefix)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefixPath.toString().startsWith(prefix)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().endsWith(suffix)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefixPath.toString().endsWith(suffix)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().contains(substring)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefixPath.toString().contains(substring)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.Path target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.equals(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.Path target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefixPath.equals(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(com.aoindustries.net.Path target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().contentEquals(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefixPath.toString().contentEquals(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return prefixPath.toString().equalsIgnoreCase(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(prefixPath.toString().equalsIgnoreCase(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return pattern.matcher(prefixPath.toString()).matches()
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(pattern.matcher(prefixPath.toString()).matches()) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
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
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return wildcardPattern.isMatch(prefixPath.toString())
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * Invokes the provided rules only when matched.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(wildcardPattern.isMatch(prefixPath.toString())) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * Invokes the provided rules only when matched.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="path">
		/**
		 * @see  PathSpace.PathMatch#getPath()
		 */
		public static class path {

			private path() {}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().startsWith(prefix)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(path.toString().startsWith(prefix)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().endsWith(suffix)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix _prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(path.toString().endsWith(suffix)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().contains(substring)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(path.toString().contains(substring)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.Path target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.equals(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.Path target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(path.equals(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#equals(java.lang.Object)
			 */
			public static Matcher equals(com.aoindustries.net.Path target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  com.aoindustries.net.Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				try {
					return equals(com.aoindustries.net.Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().contentEquals(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(path.toString().contentEquals(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return path.toString().equalsIgnoreCase(target)
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(path.toString().equalsIgnoreCase(target)) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return pattern.matcher(path.toString()).matches()
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(pattern.matcher(path.toString()).matches()) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 * Invokes the provided rules only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
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
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) {
						return wildcardPattern.isMatch(path.toString())
							? Result.MATCH
							: Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * Invokes the provided rules only when matched.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, final Iterable<? extends Rule> rules) {
				return new PathMatchMatcher() {
					@Override
					public Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain, com.aoindustries.net.pathspace.Prefix prefix, com.aoindustries.net.Path prefixPath, com.aoindustries.net.Path path) throws IOException, ServletException {
						if(wildcardPattern.isMatch(path.toString())) {
							for(Rule rule : rules) {
								Result result = rule.perform(request, response, chain);
								if(result == Result.TERMINATE) return Result.TERMINATE;
							}
							return Result.MATCH;
						} else {
							return Result.NO_MATCH;
						}
					}
				};
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * Invokes the provided rules only when matched.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}
		}

		// TODO: PathMatch-compatible for non-servlet-space root? (/**, /, /servlet-path)?

		// TODO: String.regionMatches?

		// TODO: More case-insensitive of the above?

		// TODO: CompareTo for before/after/ <=, >=?

		// </editor-fold>
	}
	// </editor-fold>
}
