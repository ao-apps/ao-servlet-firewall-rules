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
import com.aoindustries.servlet.firewall.api.FirewallContext;
import com.aoindustries.servlet.firewall.api.Matcher;
import static com.aoindustries.servlet.firewall.api.MatcherUtil.callRules;
import static com.aoindustries.servlet.firewall.api.MatcherUtil.doMatches;
import com.aoindustries.servlet.firewall.api.Rule;
import com.aoindustries.servlet.http.ServletUtil;
import com.aoindustries.util.AoCollections;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import javax.servlet.DispatcherType;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A set of base {@link Matcher} and {@link Action} implementations based on
 * the servlet API and firewall API.
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
 * @implNote  Defensive copying of collections is not performed, intentionally allowing callers to provided mutable collections.
 *            Although this should be used sparingly, it may be appropriate for rules that call-out to other APIs,
 *            such as ACLs inside of a database.
 *
 * @implNote  Arrays are not necessarily defensively copied, but the elements of the arrays might also be extracted.  Mutation of
 *            arrays is not supported.
 *
 * @implNote  This is admittedly overload-heavy.  We are paying the price here in order to have the absolutely
 *            cleanest possible rule definitions.  Perhaps a future version of Java will introduce optional parameters
 *            and this can be cleaned-up some.
 */
public class Rules {

	private Rules() {}

	// <editor-fold defaultstate="collapsed" desc="Logic">
	/**
	 * Never matches.
	 *
	 * @return  Returns {@link Matcher.Result#NO_MATCH} always
	 *
	 * @see  #or(java.lang.Iterable)
	 * @see  #or(com.aoindustries.servlet.firewall.rules.Rule[])
	 */
	// TODO: Rename NO_MATCH?
	public static final Matcher none = new Matcher() {
		@Override
		public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
			return Matcher.Result.NO_MATCH;
		}
	};

	/**
	 * Never matches.  This is useful to replace another rule with a
	 * non-matching rule, without having to comment-out the set of rules.
	 *
	 * @param  rules  The rules are never called.
	 *
	 * @return  Returns {@link #none} always
	 *
	 * @see  #none
	 */
	public static Matcher none(Iterable<? extends Rule> rules) {
		return none;
	};

	/**
	 * Never matches.  This is useful to replace another rule with a
	 * non-matching rule, without having to comment-out the sets of rules.
	 *
	 * @param  rules  The rules are never called.
	 * @param  otherwise  The rules are never called.
	 *
	 * @return  Returns {@link #none} always
	 *
	 * @see  #none
	 */
	public static Matcher none(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
		return none;
	};

	/**
	 * Never matches.  This is useful to replace another rule with a
	 * non-matching rule, without having to comment-out the set of rules.
	 *
	 * @param  rules  The rules are never called.
	 *
	 * @return  Returns {@link #none} always
	 *
	 * @see  #none
	 */
	public static Matcher none(Rule ... rules) {
		return none;
	};

	/**
	 * Never matches.  This is useful to replace another rule with a
	 * non-matching rule, without having to comment-out the sets of rules.
	 *
	 * @param  rules  The rules are never called.
	 * @param  otherwise  The rules are never called.
	 *
	 * @return  Returns {@link #none} always
	 *
	 * @see  #none
	 */
	public static Matcher none(Rule[] rules, Rule ... otherwise) {
		return none;
	};

	/**
	 * Always matches.
	 *
	 * @return  Returns {@link Matcher.Result#MATCH} always
	 */
	// TODO: Rename MATCH?
	// TODO: Java 1.8+ for all ao-servlet-firewall, for lots of Lambda reductions here?
	//       This would make semanticcms 2.0 be java 1.8+, and pragmatickm, ...
	public static final Matcher all = new Matcher() {
		@Override
		public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
			return Matcher.Result.MATCH;
		}
	};

	/**
	 * Always matches and calls all rules.
	 *
	 * @param  rules  All rules are called, up to any terminating action.
	 *
	 * @return  Returns {@link Matcher.Result#TERMINATE} if a terminating action
	 *          has occurred.  Otherwise returns {@link Matcher.Result#MATCH}.
	 */
	public static Matcher all(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				return callRules(context, rules, Matcher.Result.MATCH);
			}
		};
	}

	/**
	 * Always matches and calls all rules.  This is useful for replacing
	 * a conditional rule with an always-matching rule, without having to comment-out
	 * the "otherwise" set of rules.
	 *
	 * @param  rules  All rules are called, up to any terminating action.
	 * @param  otherwise  The rules are never called.
	 *
	 * @return  Returns {@link #all(java.lang.Iterable)} always
	 *
	 * @see  #all(java.lang.Iterable)
	 */
	public static Matcher all(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
		return all(rules);
	}

	/**
	 * Always matches and calls all rules.
	 *
	 * @param  rules  All rules are called, up to any terminating action.
	 *
	 * @return  Returns {@link Matcher.Result#TERMINATE} if a terminating action
	 *          has occurred.  Otherwise returns {@link Matcher.Result#MATCH}.
	 */
	public static Matcher all(Rule ... rules) {
		if(rules.length == 0) return all;
		return all(Arrays.asList(rules));
	}

	/**
	 * Always matches and calls all rules.  This is useful for replacing
	 * a conditional rule with an always-matching rule, without having to comment-out
	 * the "otherwise" set of rules.
	 *
	 * @param  rules  All rules are called, up to any terminating action.
	 * @param  otherwise  The rules are never called.
	 *
	 * @return  Returns {@link #all(com.aoindustries.servlet.firewall.api.Rule...)} always
	 *
	 * @see  #all(com.aoindustries.servlet.firewall.api.Rule...)
	 */
	public static Matcher all(Rule[] rules, Rule ... otherwise) {
		return all(rules);
	}

	/**
	 * Matches when all matchers match.
	 * Stops processing {@code rules} (both matchers and actions) when the first matcher does not match.
	 * Performs any actions while processing rules, up to the point stopped on first non-matching matcher.
	 *
	 * @return  {@link Matcher.Result#MATCH} when rules is empty
	 */
	public static Matcher and(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						Matcher.Result result = context.call((Matcher)rule);
						switch(result) {
							case TERMINATE :
								return Matcher.Result.TERMINATE;
							case NO_MATCH :
								return Matcher.Result.NO_MATCH;
							case MATCH :
								break;
							default :
								throw new AssertionError();
						}
					}
					if(rule instanceof Action) {
						Action.Result result = context.call((Action)rule);
						switch(result) {
							case TERMINATE :
								return Matcher.Result.TERMINATE;
							case CONTINUE :
								break;
							default :
								throw new AssertionError();
						}
					}
				}
				return Matcher.Result.MATCH;
			}
		};
	}

	/**
	 * Matches when all matchers match.
	 * Stops processing {@code rules} (both matchers and actions) when the first matcher does not match.
	 * Performs any actions while processing rules, up to the point stopped on first non-matching matcher.
	 *
	 * @param  otherwise  Performs all {@code otherwise} rules only when a matcher in {@code matches} does not match.
	 *
	 * @return  {@link Matcher.Result#MATCH} when rules is empty
	 */
	public static Matcher and(final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
		return new Matcher() {
			@Override
			public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				boolean matched = true;
				RULES :
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						Matcher.Result result = context.call((Matcher)rule);
						switch(result) {
							case TERMINATE :
								return Matcher.Result.TERMINATE;
							case NO_MATCH :
								matched = false;
								// Move on to otherwise
								break RULES;
							case MATCH :
								// Continue to action
								break;
							default :
								throw new AssertionError();
						}
					}
					if(rule instanceof Action) {
						Action.Result result = context.call((Action)rule);
						switch(result) {
							case TERMINATE :
								return Matcher.Result.TERMINATE;
							case CONTINUE :
								// Continue to next rule
								break;
							default :
								throw new AssertionError();
						}
					}
				}
				if(matched) {
					return Matcher.Result.MATCH;
				} else {
					return callRules(context, otherwise, Matcher.Result.NO_MATCH);
				}
			}
		};
	}

	/**
	 * Matches when all matchers match.
	 * Stops processing {@code rules} (both matchers and actions) when the first matcher does not match.
	 * Performs any actions while processing rules, up to the point stopped on first non-matching matcher.
	 *
	 * @return  {@link Matcher.Result#MATCH} when rules is empty
	 */
	// TODO: Is "all" the best name for this?  Maybe "and" / "or" instead of "all" / "any"?
	//       This is because it might be expected that all rules will be invoked, not as a matcher.
	//       Then "all" could be created that simply calls all rules, useful inside "and" / "or" to not terminate?
	public static Matcher and(Rule ... rules) {
		if(rules.length == 0) return all;
		return and(Arrays.asList(rules));
	}

	/**
	 * Matches when all matchers match.
	 * Stops processing {@code rules} (both matchers and actions) when the first matcher does not match.
	 * Performs any actions while processing rules, up to the point stopped on first non-matching matcher.
	 *
	 * @param  otherwise  Performs all {@code otherwise} rules only when a matcher in {@code matches} does not match.
	 *
	 * @return  {@link Matcher.Result#MATCH} when rules is empty
	 */
	public static Matcher and(Rule[] rules, Rule ... otherwise) {
		if(otherwise.length == 0) return and(rules);
		return and(Arrays.asList(rules), Arrays.asList(otherwise));
	}

	/**
	 * Matches when any matchers match.
	 * Stops processing matchers once the first match is found.
	 * Begins processing actions once the first match is found.
	 *
	 * @return  {@link Matcher.Result#NO_MATCH} when rules is empty
	 *
	 * @see  #none
	 */
	public static Matcher or(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				boolean matched = false;
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						if(!matched) {
							Matcher.Result result = context.call((Matcher)rule);
							switch(result) {
								case TERMINATE :
									return Matcher.Result.TERMINATE;
								case MATCH :
									matched = true;
									break;
								case NO_MATCH :
									// Continue lookning for first match
									break;
								default :
									throw new AssertionError();
							}
						}
					}
					if(rule instanceof Action) {
						if(matched) {
							Action.Result result = context.call((Action)rule);
							switch(result) {
								case TERMINATE :
									return Matcher.Result.TERMINATE;
								case CONTINUE :
									// Continue with any additional actions
									break;
								default :
									throw new AssertionError();
							}
						}
					}
				}
				return matched ? Matcher.Result.MATCH : Matcher.Result.NO_MATCH;
			}
		};
	}

	/**
	 * Matches when any matchers match.
	 * Stops processing matchers once the first match is found.
	 * Begins processing actions once the first match is found.
	 *
	 * @param  otherwise  Performs all {@code otherwise} rules only when no matcher in {@code matches} matches.
	 *
	 * @return  {@link Matcher.Result#NO_MATCH} when rules is empty
	 *
	 * @see  #none
	 */
	public static Matcher or(final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
		return new Matcher() {
			@Override
			public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				boolean matched = false;
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						if(!matched) {
							Matcher.Result result = context.call((Matcher)rule);
							switch(result) {
								case TERMINATE :
									return Matcher.Result.TERMINATE;
								case MATCH :
									matched = true;
									break;
								case NO_MATCH :
									// Continue lookning for first match
									break;
								default :
									throw new AssertionError();
							}
						}
					}
					if(rule instanceof Action) {
						if(matched) {
							Action.Result result = context.call((Action)rule);
							switch(result) {
								case TERMINATE :
									return Matcher.Result.TERMINATE;
								case CONTINUE :
									// Continue with any additional actions
									break;
								default :
									throw new AssertionError();
							}
						}
					}
				}
				if(matched) {
					return Matcher.Result.MATCH;
				} else {
					return callRules(context, otherwise, Matcher.Result.NO_MATCH);
				}
			}
		};
	}

	/**
	 * Matches when any matchers match.
	 * Stops processing matchers once the first match is found.
	 * Begins processing actions once the first match is found.
	 *
	 * @return  {@link Matcher.Result#NO_MATCH} when rules is empty
	 *
	 * @see  #none
	 */
	public static Matcher or(Rule ... rules) {
		if(rules.length == 0) return none;
		return or(Arrays.asList(rules));
	}

	/**
	 * Matches when any matchers match.
	 * Stops processing matchers once the first match is found.
	 * Begins processing actions once the first match is found.
	 *
	 * @param  otherwise  Performs all {@code otherwise} rules only when no matcher in {@code matches} matches.
	 *
	 * @return  {@link Matcher.Result#NO_MATCH} when rules is empty
	 *
	 * @see  #none
	 */
	public static Matcher or(Rule[] rules, Rule ... otherwise) {
		if(otherwise.length == 0) return or(rules);
		return or(Arrays.asList(rules), Arrays.asList(otherwise));
	}

	/**
	 * Negates a match.
	 *
	 * TODO: What would it mean to handle multiple rules?  Or best used with "not/any" "not/all"?
	 * TODO: Should the negation be passed on to them regarding their invocation of any nested actions?
	 * TODO: What would "otherwise" be?
	 */
	public static Matcher not(final Matcher matcher) {
		return new Matcher() {
			@Override
			public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				Matcher.Result result = context.call(matcher);
				switch(result) {
					case TERMINATE : return Matcher.Result.TERMINATE;
					case MATCH     : return Matcher.Result.NO_MATCH;
					case NO_MATCH  : return Matcher.Result.MATCH;
					default        : throw new AssertionError();
				}
			}
		};
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="General">
	/**
	 * Performs no action.
	 *
	 * @return  Returns {@link Action.Result#CONTINUE} always
	 */
	public static final Action CONTINUE = new Action() {
		@Override
		public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
			return Action.Result.CONTINUE;
		}
	};

	/**
	 * Performs no action and terminates request processing.
	 *
	 * @return  Returns {@link Action.Result#TERMINATE} always
	 */
	public static final Action TERMINATE = new Action() {
		@Override
		public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
			return Action.Result.TERMINATE;
		}
	};

	// TODO: Options to throw exceptions? IOException, ServletException, SkipPageException (wrapped)

	// </editor-fold>

	// TODO: Registration?
	// TODO: Servlet/HttpServlet/ServletConfig/ServletRegistration anything useful at filter processing stage?

	// TODO: RequestDispatcher (and all associated constants)?

	// <editor-fold defaultstate="collapsed" desc="chain">
	/**
	 * @see  FilterChain
	 */
	public static class chain {

		private chain() {}

		/**
		 * @see  FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
		 *
		 * @return  Returns {@link Action.Result#TERMINATE} always
		 */
		public static final Action doFilter = new Action() {
			@Override
			public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
				chain.doFilter(request, response);
				return Action.Result.TERMINATE;
			}
		};
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="servletContext">
	/**
	 * @see  ServletContext
	 *
	 * // TODO: Name just "context", but what if we have FirewallContext?
	 */
	public static class servletContext {

		private servletContext() {}

		// TODO: orderedLibs, tempDir (from constants?)

		// TODO: getContextPath()?

		// TODO: EffectiveMajorVersion / EffectiveMinorVersion / MajorVersion, MinorVersion?

		// TODO: Resources?
		//     TODO: getMimeType
		//     TODO: getResourcePaths
		//     TODO: getResource
		//     TODO: getResourceAsStream
		//     TODO: getRealPath

		// TODO: getRequestDispatcher?
		// TODO: hasRequestDispatcher?

		// TODO: getNamedDispatcher?
		// TODO: hasNamedDispatcher?

		/**
		 * @see  ServletContext#log(java.lang.String)
		 *
		 * @return  Returns {@link Action.Result#CONTINUE} always
		 */
		public static final Action log = new Action() {
			@Override
			public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
				// TODO: Could log more
				// TODO: PathPrefix, if present.  Or a way for PathPrefix to register loggers on the FirewallContext
				// TODO: Also TRACE/stack/integration for logger on FirewallContext?
				request.getServletContext().log("request.servetPath = " + request.getServletPath()); // TODO: more + ", prefix = " + prefix + ", prefixPath = " + prefixPath + ", path = " + path);
				return Action.Result.CONTINUE;
			}
		};

		/**
		 * @see  ServletContext#log(java.lang.String)
		 *
		 * @return  Returns {@link Action.Result#CONTINUE} always
		 */
		// TODO: Version with a Callable<String>? Java 1.8 functional interface?
		public static Action log(final String message) {
			return new Action() {
				@Override
				public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
					// TODO: Could log more or less
					request.getServletContext().log(message);
					return Action.Result.CONTINUE;
				}
			};
		}

		// TODO: ServerInfo?

		// TODO: InitParameters

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: ServletContextName?

		// TODO: getServletRegistration?

		// TODO: getFilterRegistration?

		// TODO: getSessionCookieConfig?

		// TODO: SessionTrackingModes?

		// TODO: JspConfigDescriptor?

		// TODO: declareRoles?
	}
	// </editor-fold>

	// TODO: Filter name and init parameters from ao-servlet-firewall-filter?

	// <editor-fold defaultstate="collapsed" desc="request">
	/**
	 * @see  ServletRequest
	 * @see  HttpServletRequest
	 */
	public static class request {

		private request() {}

		// <editor-fold defaultstate="collapsed" desc="ServletRequest">

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: getCharacterEncoding?
		// TODO: setCharacterEncoding?

		// TODO: getContentLength?

		// TODO: getContentType?

		// TODO: Parameters

		// TODO: getProtocol

		// TODO: getScheme

		// TODO: getServerName/getServerPort

		// TODO: getRemoteAddr/getRemoteHost/getRemotePort

		// TODO: getLocale(s)

		// TODO: isSecure?

		// TODO: getRequestDispatcher?

		// TODO: getLocalAddr/getLocalName/getLocalPort

		// TODO: startAsync?

		// TODO: isAsyncStarted/Supported?

		// TODO: AsyncContext (and all associated constants)?

		// <editor-fold defaultstate="collapsed" desc="dispatcherType">
		/**
		 * @see  ServletRequest#getDispatcherType()
		 */
		public static class dispatcherType {

			private dispatcherType() {}

			private static class Is implements Matcher {
				private final DispatcherType dispatcherType;
				private Is(DispatcherType dispatcherType) {
					this.dispatcherType = dispatcherType;
				}
				@Override
				public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
					return request.getDispatcherType() == dispatcherType
						? Matcher.Result.MATCH
						: Matcher.Result.NO_MATCH;
				}
			}

			/**
			 * Matches one given {@link DispatcherType}.
			 */
			public static Matcher is(DispatcherType dispatcherType) {
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
			 * Matches one given {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(final DispatcherType dispatcherType, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(request.getDispatcherType() == dispatcherType, context, rules);
					}
				};
			}

			/**
			 * Matches one given {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher is(final DispatcherType dispatcherType, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(request.getDispatcherType() == dispatcherType, context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches one given {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(DispatcherType dispatcherType, Rule ... rules) {
				if(rules.length == 0) return is(dispatcherType);
				return is(dispatcherType, Arrays.asList(rules));
			}

			/**
			 * Matches one given {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher is(DispatcherType dispatcherType, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return is(dispatcherType, rules);
				return is(dispatcherType, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given iterable of {@link DispatcherType}.
			 */
			public static Matcher in(final Iterable<? extends DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
						DispatcherType type = request.getDispatcherType();
						for(DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) return Matcher.Result.MATCH;
						}
						return Matcher.Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 */
			public static Matcher in(final EnumSet<? extends DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
						return dispatcherTypes.contains(request.getDispatcherType())
							? Matcher.Result.MATCH
							: Matcher.Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 */
			public static Matcher in(DispatcherType ... dispatcherTypes) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0]);
				return in(EnumSet.of(dispatcherTypes[0], dispatcherTypes));
			}

			/**
			 * Matches any of a given iterable of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Iterable<? extends DispatcherType> dispatcherTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						boolean matches = false;
						DispatcherType type = request.getDispatcherType();
						for(DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) {
								matches = true;
								break;
							}
						}
						return doMatches(matches, context, rules);
					}
				};
			}

			/**
			 * Matches any of a given iterable of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(final Iterable<? extends DispatcherType> dispatcherTypes, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						boolean matches = false;
						DispatcherType type = request.getDispatcherType();
						for(DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) {
								matches = true;
								break;
							}
						}
						return doMatches(matches, context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final EnumSet<? extends DispatcherType> dispatcherTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(dispatcherTypes.contains(request.getDispatcherType()), context, rules);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(final EnumSet<? extends DispatcherType> dispatcherTypes, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(dispatcherTypes.contains(request.getDispatcherType()), context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(DispatcherType[] dispatcherTypes, Iterable<? extends Rule> rules) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0], rules);
				return in(EnumSet.of(dispatcherTypes[0], dispatcherTypes), rules);
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(DispatcherType[] dispatcherTypes, Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0], rules, otherwise);
				return in(EnumSet.of(dispatcherTypes[0], dispatcherTypes), rules, otherwise);
			}

			/**
			 * Matches any of a given iterable of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(Iterable<? extends DispatcherType> dispatcherTypes, Rule ... rules) {
				if(rules.length == 0) return in(dispatcherTypes);
				return in(dispatcherTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given iterable of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(Iterable<? extends DispatcherType> dispatcherTypes, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(dispatcherTypes, rules);
				return in(dispatcherTypes, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(EnumSet<? extends DispatcherType> dispatcherTypes, Rule ... rules) {
				if(rules.length == 0) return in(dispatcherTypes);
				return in(dispatcherTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(EnumSet<? extends DispatcherType> dispatcherTypes, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(dispatcherTypes, rules);
				return in(dispatcherTypes, Arrays.asList(rules), Arrays.asList(otherwise)); // TODO: Arrays.asList perform AoCollections optimalCopy, document as arrays defensively copied?
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(DispatcherType[] dispatcherTypes, Rule ... rules) {
				if(dispatcherTypes.length == 0) return none;
				if(dispatcherTypes.length == 1) return is(dispatcherTypes[0], rules);
				if(rules.length == 0) return in(dispatcherTypes);
				return in(dispatcherTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(DispatcherType[] dispatcherTypes, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(dispatcherTypes, rules);
				return in(dispatcherTypes, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches {@link DispatcherType#FORWARD}.
			 */
			public static final Matcher isForward = new Is(DispatcherType.FORWARD);

			/**
			 * Matches {@link DispatcherType#FORWARD}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isForward(Iterable<? extends Rule> rules) {
				return is(DispatcherType.FORWARD, rules);
			}

			/**
			 * Matches {@link DispatcherType#FORWARD}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isForward(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(DispatcherType.FORWARD, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#FORWARD}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isForward(Rule ... rules) {
				return is(DispatcherType.FORWARD, rules);
			}

			/**
			 * Matches {@link DispatcherType#FORWARD}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isForward(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isForward(rules);
				return is(DispatcherType.FORWARD, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#INCLUDE}.
			 */
			public static final Matcher isInclude = new Is(DispatcherType.INCLUDE);

			/**
			 * Matches {@link DispatcherType#INCLUDE}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isInclude(Iterable<? extends Rule> rules) {
				return is(DispatcherType.INCLUDE, rules);
			}

			/**
			 * Matches {@link DispatcherType#INCLUDE}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isInclude(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(DispatcherType.INCLUDE, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#INCLUDE}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isInclude(Rule ... rules) {
				return is(DispatcherType.INCLUDE, rules);
			}

			/**
			 * Matches {@link DispatcherType#INCLUDE}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isInclude(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isInclude(rules);
				return is(DispatcherType.INCLUDE, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#REQUEST}.
			 */
			public static final Matcher isRequest = new Is(DispatcherType.REQUEST);

			/**
			 * Matches {@link DispatcherType#REQUEST}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isRequest(Iterable<? extends Rule> rules) {
				return is(DispatcherType.REQUEST, rules);
			}

			/**
			 * Matches {@link DispatcherType#REQUEST}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isRequest(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(DispatcherType.REQUEST, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#REQUEST}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isRequest(Rule ... rules) {
				return is(DispatcherType.REQUEST, rules);
			}

			/**
			 * Matches {@link DispatcherType#REQUEST}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isRequest(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isRequest(rules);
				return is(DispatcherType.REQUEST, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#ASYNC}.
			 */
			public static final Matcher isAsync = new Is(DispatcherType.ASYNC);

			/**
			 * Matches {@link DispatcherType#ASYNC}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isAsync(Iterable<? extends Rule> rules) {
				return is(DispatcherType.ASYNC, rules);
			}

			/**
			 * Matches {@link DispatcherType#ASYNC}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isAsync(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(DispatcherType.ASYNC, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#ASYNC}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isAsync(Rule ... rules) {
				return is(DispatcherType.ASYNC, rules);
			}

			/**
			 * Matches {@link DispatcherType#ASYNC}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isAsync(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isAsync(rules);
				return is(DispatcherType.ASYNC, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#ERROR}.
			 */
			public static final Matcher isError = new Is(DispatcherType.ERROR);

			/**
			 * Matches {@link DispatcherType#ERROR}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isError(Iterable<? extends Rule> rules) {
				return is(DispatcherType.ERROR, rules);
			}

			/**
			 * Matches {@link DispatcherType#ERROR}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isError(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(DispatcherType.ERROR, rules, otherwise);
			}

			/**
			 * Matches {@link DispatcherType#ERROR}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isError(Rule ... rules) {
				return is(DispatcherType.ERROR, rules);
			}

			/**
			 * Matches {@link DispatcherType#ERROR}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isError(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isError(rules);
				return is(DispatcherType.ERROR, rules, otherwise);
			}
		}
		// </editor-fold>

		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="HttpServletRequest">

		// <editor-fold defaultstate="collapsed" desc="authType">
		/**
		 * TODO: Support nulls or a method for noAuthType?
		 *
		 * @see  HttpServletRequest#getAuthType()
		 */
		public static class authType {

			private authType() {}

			private static class Is implements Matcher {
				private final String authType;
				private Is(String authType) {
					this.authType = authType;
				}
				@Override
				public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
					String type = request.getAuthType();
					return type != null && type.equals(authType)
						? Matcher.Result.MATCH
						: Matcher.Result.NO_MATCH;
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(final String authType, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						String type = request.getAuthType();
						return doMatches(type != null && type.equals(authType), context, rules);
					}
				};
			}

			/**
			 * Matches one given {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher is(final String authType, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						String type = request.getAuthType();
						return doMatches(type != null && type.equals(authType), context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches one given {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(String authType, Rule ... rules) {
				if(rules.length == 0) return is(authType);
				return is(authType, Arrays.asList(rules));
			}

			/**
			 * Matches one given {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher is(String authType, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return is(authType, rules);
				return is(authType, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 */
			public static Matcher in(final Iterable<? extends String> authTypes) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
						String type = request.getAuthType();
						if(type != null) {
							for(String authType : authTypes) {
								if(type.equals(authType)) return Matcher.Result.MATCH;
							}
						}
						return Matcher.Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 */
			public static Matcher in(final Collection<? extends String> authTypes) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
						String type = request.getAuthType();
						return type != null && authTypes.contains(type)
							? Matcher.Result.MATCH
							: Matcher.Result.NO_MATCH;
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Iterable<? extends String> authTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						boolean matches = false;
						String type = request.getAuthType();
						if(type != null) {
							for(String authType : authTypes) {
								if(type.equals(authType)) {
									matches = true;
									break;
								}
							}
						}
						return doMatches(matches, context, rules);
					}
				};
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(final Iterable<? extends String> authTypes, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						boolean matches = false;
						String type = request.getAuthType();
						if(type != null) {
							for(String authType : authTypes) {
								if(type.equals(authType)) {
									matches = true;
									break;
								}
							}
						}
						return doMatches(matches, context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Collection<? extends String> authTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						String type = request.getAuthType();
						return doMatches(type != null && authTypes.contains(type), context, rules);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(final Collection<? extends String> authTypes, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						String type = request.getAuthType();
						return doMatches(type != null && authTypes.contains(type), context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(String[] authTypes, Iterable<? extends Rule> rules) {
				if(authTypes.length == 0) return none;
				if(authTypes.length == 1) return is(authTypes[0], rules);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(authTypes)), rules);
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(String[] authTypes, Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				if(authTypes.length == 0) return none;
				if(authTypes.length == 1) return is(authTypes[0], rules);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(authTypes)), rules, otherwise);
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(Iterable<? extends String> authTypes, Rule ... rules) {
				if(rules.length == 0) return in(authTypes);
				return in(authTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(Iterable<? extends String> authTypes, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(authTypes, rules);
				return in(authTypes, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(Collection<? extends String> authTypes, Rule ... rules) {
				if(rules.length == 0) return in(authTypes);
				return in(authTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(Collection<? extends String> authTypes, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(authTypes, rules);
				return in(authTypes, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(String[] authTypes, Rule ... rules) {
				if(authTypes.length == 0) return none;
				if(authTypes.length == 1) return is(authTypes[0], rules);
				if(rules.length == 0) return in(authTypes);
				return in(authTypes, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getAuthType()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(String[] authTypes, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(authTypes, rules);
				return in(authTypes, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 */
			public static final Matcher isBasic = new Is(HttpServletRequest.BASIC_AUTH);

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isBasic(Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.BASIC_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isBasic(Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return is(HttpServletRequest.BASIC_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isBasic(Rule ... rules) {
				return is(HttpServletRequest.BASIC_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#BASIC_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isBasic(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isBasic(rules);
				return is(HttpServletRequest.BASIC_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 */
			public static final Matcher isForm = new Is(HttpServletRequest.FORM_AUTH);

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isForm(Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.FORM_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isForm(Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return is(HttpServletRequest.FORM_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isForm(Rule ... rules) {
				return is(HttpServletRequest.FORM_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#FORM_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isForm(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isForm(rules);
				return is(HttpServletRequest.FORM_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 */
			public static final Matcher isClientCert = new Is(HttpServletRequest.CLIENT_CERT_AUTH);

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isClientCert(Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.CLIENT_CERT_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isClientCert(Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return is(HttpServletRequest.CLIENT_CERT_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isClientCert(Rule ... rules) {
				return is(HttpServletRequest.CLIENT_CERT_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#CLIENT_CERT_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isClientCert(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isClientCert(rules);
				return is(HttpServletRequest.CLIENT_CERT_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 */
			public static final Matcher isDigest = new Is(HttpServletRequest.DIGEST_AUTH);

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isDigest(Iterable<? extends Rule> rules) {
				return is(HttpServletRequest.DIGEST_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isDigest(Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return is(HttpServletRequest.DIGEST_AUTH, rules, otherwise);
			}

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isDigest(Rule ... rules) {
				return is(HttpServletRequest.DIGEST_AUTH, rules);
			}

			/**
			 * Matches {@link HttpServletRequest#DIGEST_AUTH}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isDigest(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isDigest(rules);
				return is(HttpServletRequest.DIGEST_AUTH, rules, otherwise);
			}
		}
		// </editor-fold>

		// TODO: Cookies?

		// TODO: Headers?

		// <editor-fold defaultstate="collapsed" desc="method">
		/**
		 * @see  HttpServletRequest#getMethod()
		 */
		public static class method {

			private method() {}

			private static class Is implements Matcher {
				private final String method;
				private Is(String method) {
					this.method = method;
				}
				@Override
				public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
					return request.getMethod().equals(method)
						? Matcher.Result.MATCH
						: Matcher.Result.NO_MATCH;
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(final String method, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(request.getMethod().equals(method), context, rules);
					}
				};
			}

			/**
			 * Matches one given {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher is(final String method, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(request.getMethod().equals(method), context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches one given {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(String method, Rule ... rules) {
				if(rules.length == 0) return is(method);
				return is(method, Arrays.asList(rules));
			}

			/**
			 * Matches one given {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher is(String method, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return is(method, rules);
				return is(method, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 */
			public static Matcher in(final Iterable<? extends String> methods) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
						String m = request.getMethod();
						for(String method : methods) {
							if(m.equals(method)) return Matcher.Result.MATCH;
						}
						return Matcher.Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 */
			public static Matcher in(final Collection<? extends String> methods) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) {
						return methods.contains(request.getMethod())
							? Matcher.Result.MATCH
							: Matcher.Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 */
			// TODO: Allow single-string for methods and parse it splitting on comma/space?
			public static Matcher in(String ... methods) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0]);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(methods)));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Iterable<? extends String> methods, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						boolean matches = false;
						String m = request.getMethod();
						for(String method : methods) {
							if(m.equals(method)) {
								matches = true;
								break;
							}
						}
						return doMatches(matches, context, rules);
					}
				};
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(final Iterable<? extends String> methods, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						boolean matches = false;
						String m = request.getMethod();
						for(String method : methods) {
							if(m.equals(method)) {
								matches = true;
								break;
							}
						}
						return doMatches(matches, context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Collection<? extends String> methods, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(methods.contains(request.getMethod()), context, rules);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(final Collection<? extends String> methods, final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
				return new Matcher() {
					@Override
					public Matcher.Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(methods.contains(request.getMethod()), context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			// TODO: Allow single-string for methods and parse it splitting on comma/space?
			public static Matcher in(String[] methods, Iterable<? extends Rule> rules) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0], rules);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(methods)), rules);
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			// TODO: Allow single-string for methods and parse it splitting on comma/space?
			public static Matcher in(String[] methods, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0], rules, otherwise);
				return in(AoCollections.unmodifiableCopySet(Arrays.asList(methods)), rules, otherwise);
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(Iterable<? extends String> methods, Rule ... rules) {
				if(rules.length == 0) return in(methods);
				return in(methods, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given iterable of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(Iterable<? extends String> methods, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(methods, rules);
				return in(methods, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(Collection<? extends String> methods, Rule ... rules) {
				if(rules.length == 0) return in(methods);
				return in(methods, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher in(Collection<? extends String> methods, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(methods, rules);
				return in(methods, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			// TODO: Allow single-string for methods and parse it splitting on comma/space?
			public static Matcher in(String[] methods, Rule ... rules) {
				if(methods.length == 0) return none;
				if(methods.length == 1) return is(methods[0], rules);
				if(rules.length == 0) return in(methods);
				return in(methods, Arrays.asList(rules));
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			// TODO: Allow single-string for methods and parse it splitting on comma/space?
			public static Matcher in(String[] methods, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return in(methods, rules);
				return in(methods, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 */
			public static final Matcher isDelete = new Is(ServletUtil.METHOD_DELETE);

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isDelete(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_DELETE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isDelete(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_DELETE, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isDelete(Rule ... rules) {
				return is(ServletUtil.METHOD_DELETE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_DELETE}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isDelete(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isDelete(rules);
				return is(ServletUtil.METHOD_DELETE, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 */
			public static final Matcher isHead = new Is(ServletUtil.METHOD_HEAD);

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isHead(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_HEAD, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isHead(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_HEAD, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isHead(Rule ... rules) {
				return is(ServletUtil.METHOD_HEAD, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_HEAD}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isHead(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isHead(rules);
				return is(ServletUtil.METHOD_HEAD, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 */
			public static final Matcher isGet = new Is(ServletUtil.METHOD_GET);

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isGet(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_GET, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isGet(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_GET, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isGet(Rule ... rules) {
				return is(ServletUtil.METHOD_GET, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_GET}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isGet(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isGet(rules);
				return is(ServletUtil.METHOD_GET, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 */
			public static final Matcher isOptions = new Is(ServletUtil.METHOD_OPTIONS);

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isOptions(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_OPTIONS, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isOptions(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_OPTIONS, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isOptions(Rule ... rules) {
				return is(ServletUtil.METHOD_OPTIONS, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_OPTIONS}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isOptions(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isOptions(rules);
				return is(ServletUtil.METHOD_OPTIONS, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 */
			public static final Matcher isPost = new Is(ServletUtil.METHOD_POST);

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isPost(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_POST, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isPost(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_POST, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isPost(Rule ... rules) {
				return is(ServletUtil.METHOD_POST, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_POST}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isPost(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isPost(rules);
				return is(ServletUtil.METHOD_POST, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 */
			public static final Matcher isPut = new Is(ServletUtil.METHOD_PUT);

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isPut(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_PUT, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isPut(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_PUT, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isPut(Rule ... rules) {
				return is(ServletUtil.METHOD_PUT, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_PUT}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isPut(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isPut(rules);
				return is(ServletUtil.METHOD_PUT, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 */
			public static final Matcher isTrace = new Is(ServletUtil.METHOD_TRACE);

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isTrace(Iterable<? extends Rule> rules) {
				return is(ServletUtil.METHOD_TRACE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isTrace(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return is(ServletUtil.METHOD_TRACE, rules, otherwise);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher isTrace(Rule ... rules) {
				return is(ServletUtil.METHOD_TRACE, rules);
			}

			/**
			 * Matches {@link ServletUtil#METHOD_TRACE}.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 */
			public static Matcher isTrace(Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return isTrace(rules);
				return is(ServletUtil.METHOD_TRACE, rules, otherwise);
			}
		}
		// </editor-fold>

		// TODO: pathInfo?

		// TODO: pathTranslated?

		// TODO: getContextPath?

		// TODO: queryString?

		// TODO: getRemoteUser?

		// TODO: isUserInRole

		// TODO: getUserPrincipal

		// TODO: getRequestURI?

		// TODO: getRequestURL?

		// TODO: getServletPath? (and other things like getting forward path, include path, ...)  Combined path with pathInfo

		// TODO: Session stuff (with potential to set in non-terminating action)?
		//     TODO: getRequestedSessionId
		//     TODO: getSession
		//     TODO: isRequestedSessionIdValid
		//     TODO: isRequestedSessionIdFromCookie
		//     TODO: isRequestedSessionIdFromURL

		// TODO: authenticate?

		// TODO: login?

		/**
		 * @see  HttpServletRequest#logout()
		 *
		 * @return  Returns {@link Action.Result#CONTINUE} always
		 */
		public static final Action logout = new Action() {
			@Override
			public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException {
				request.logout();
				return Action.Result.CONTINUE;
			}
		};

		// TODO: Parts?
		//     TODO: Part (to block/require file uploads) - See ao-servlet-filters for helpful upload handler

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

		// TODO: getCharacterEncoding?
		// TODO: setCharacterEncoding?

		// TODO: getContentType?
		// TODO: setContentType?

		// TODO: setContentLength?

		// TODO: getBufferSize?
		// TODO: setBufferSize?
		// TODO: flushBuffer?
		// TODO: resetBuffer?

		// TODO: isCommitted?

		// TODO: reset?

		// TODO: getLocale?
		// TODO: setLocale?

		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="HttpServletResponse">

		// TODO: addCookie?

		// TODO: headers

		// TODO: encodeURL/encodeRedirectURL?

		// TODO: getStatus
		// TODO: setStatus

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
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			private static class SendError implements Action {
				private final int sc;
				private SendError(int sc) {
					this.sc = sc;
				}
				@Override
				public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
					response.sendError(sc);
					return Action.Result.TERMINATE;
				}
			}

			/**
			 * Sends the provided HTTP status code.
			 *
			 * @see  HttpServletResponse#sendError(int)
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
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
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action sendError(final int sc, final String message) {
				return new Action() {
					@Override
					public Action.Result perform(FirewallContext context, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
						response.sendError(sc, message);
						return Action.Result.TERMINATE;
					}
				};
			}

			/**
			 * @see  HttpServletResponse#SC_CONTINUE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action CONTINUE = new SendError(HttpServletResponse.SC_CONTINUE);

			/**
			 * @see  HttpServletResponse#SC_SWITCHING_PROTOCOLS
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action SWITCHING_PROTOCOLS = new SendError(HttpServletResponse.SC_SWITCHING_PROTOCOLS);

			/**
			 * @see  HttpServletResponse#SC_OK
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action OK = new SendError(HttpServletResponse.SC_OK);

			/**
			 * @see  HttpServletResponse#SC_CREATED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action CREATED = new SendError(HttpServletResponse.SC_CREATED);

			/**
			 * @see  HttpServletResponse#SC_ACCEPTED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action ACCEPTED = new SendError(HttpServletResponse.SC_ACCEPTED);

			/**
			 * @see  HttpServletResponse#SC_NON_AUTHORITATIVE_INFORMATION
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action NON_AUTHORITATIVE_INFORMATION = new SendError(HttpServletResponse.SC_NON_AUTHORITATIVE_INFORMATION);

			/**
			 * @see  HttpServletResponse#SC_NO_CONTENT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action NO_CONTENT = new SendError(HttpServletResponse.SC_NO_CONTENT);

			/**
			 * @see  HttpServletResponse#SC_RESET_CONTENT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action RESET_CONTENT = new SendError(HttpServletResponse.SC_RESET_CONTENT);

			/**
			 * @see  HttpServletResponse#SC_PARTIAL_CONTENT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action PARTIAL_CONTENT = new SendError(HttpServletResponse.SC_PARTIAL_CONTENT);

			/**
			 * @see  HttpServletResponse#SC_MULTIPLE_CHOICES
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action MULTIPLE_CHOICES = new SendError(HttpServletResponse.SC_MULTIPLE_CHOICES);

			/**
			 * @see  HttpServletResponse#SC_MOVED_PERMANENTLY
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action MOVED_PERMANENTLY = new SendError(HttpServletResponse.SC_MOVED_PERMANENTLY);

			/**
			 * @see  HttpServletResponse#SC_FOUND
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action FOUND = new SendError(HttpServletResponse.SC_FOUND);

			/**
			 * @see  HttpServletResponse#SC_MOVED_TEMPORARILY
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 *
			 * @deprecated  Please use {@link #FOUND}
			 */
			@Deprecated
			public static final Action MOVED_TEMPORARILY = FOUND;

			/**
			 * @see  HttpServletResponse#SC_SEE_OTHER
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action SEE_OTHER = new SendError(HttpServletResponse.SC_SEE_OTHER);

			/**
			 * @see  HttpServletResponse#SC_NOT_MODIFIED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action NOT_MODIFIED = new SendError(HttpServletResponse.SC_NOT_MODIFIED);

			/**
			 * @see  HttpServletResponse#SC_USE_PROXY
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action USE_PROXY = new SendError(HttpServletResponse.SC_USE_PROXY);

			/**
			 * @see  HttpServletResponse#SC_TEMPORARY_REDIRECT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action TEMPORARY_REDIRECT = new SendError(HttpServletResponse.SC_TEMPORARY_REDIRECT);

			/**
			 * @see  HttpServletResponse#SC_BAD_REQUEST
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action BAD_REQUEST = new SendError(HttpServletResponse.SC_BAD_REQUEST);

			/**
			 * @see  HttpServletResponse#SC_UNAUTHORIZED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action UNAUTHORIZED = new SendError(HttpServletResponse.SC_UNAUTHORIZED);

			/**
			 * @see  HttpServletResponse#SC_PAYMENT_REQUIRED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action PAYMENT_REQUIRED = new SendError(HttpServletResponse.SC_PAYMENT_REQUIRED);

			/**
			 * @see  HttpServletResponse#SC_FORBIDDEN
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action FORBIDDEN = new SendError(HttpServletResponse.SC_FORBIDDEN);

			/**
			 * @see  HttpServletResponse#SC_NOT_FOUND
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action NOT_FOUND = new SendError(HttpServletResponse.SC_NOT_FOUND);

			/**
			 * @see  HttpServletResponse#SC_METHOD_NOT_ALLOWED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action METHOD_NOT_ALLOWED = new SendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);

			/**
			 * @see  HttpServletResponse#SC_NOT_ACCEPTABLE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action NOT_ACCEPTABLE = new SendError(HttpServletResponse.SC_NOT_ACCEPTABLE);

			/**
			 * @see  HttpServletResponse#SC_PROXY_AUTHENTICATION_REQUIRED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action PROXY_AUTHENTICATION_REQUIRED = new SendError(HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED);

			/**
			 * @see  HttpServletResponse#SC_REQUEST_TIMEOUT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action REQUEST_TIMEOUT = new SendError(HttpServletResponse.SC_REQUEST_TIMEOUT);

			/**
			 * @see  HttpServletResponse#SC_CONFLICT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action CONFLICT = new SendError(HttpServletResponse.SC_CONFLICT);

			/**
			 * @see  HttpServletResponse#SC_GONE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action GONE = new SendError(HttpServletResponse.SC_GONE);

			/**
			 * @see  HttpServletResponse#SC_LENGTH_REQUIRED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action LENGTH_REQUIRED = new SendError(HttpServletResponse.SC_LENGTH_REQUIRED);

			/**
			 * @see  HttpServletResponse#SC_PRECONDITION_FAILED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action PRECONDITION_FAILED = new SendError(HttpServletResponse.SC_PRECONDITION_FAILED);

			/**
			 * @see  HttpServletResponse#SC_REQUEST_ENTITY_TOO_LARGE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action REQUEST_ENTITY_TOO_LARGE = new SendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);

			/**
			 * @see  HttpServletResponse#SC_REQUEST_URI_TOO_LONG
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action REQUEST_URI_TOO_LONG = new SendError(HttpServletResponse.SC_REQUEST_URI_TOO_LONG);

			/**
			 * @see  HttpServletResponse#SC_UNSUPPORTED_MEDIA_TYPE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action UNSUPPORTED_MEDIA_TYPE = new SendError(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);

			/**
			 * @see  HttpServletResponse#SC_REQUESTED_RANGE_NOT_SATISFIABLE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action REQUESTED_RANGE_NOT_SATISFIABLE = new SendError(HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE);

			/**
			 * @see  HttpServletResponse#SC_EXPECTATION_FAILED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action EXPECTATION_FAILED = new SendError(HttpServletResponse.SC_EXPECTATION_FAILED);

			/**
			 * @see  HttpServletResponse#SC_INTERNAL_SERVER_ERROR
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action INTERNAL_SERVER_ERROR = new SendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

			/**
			 * @see  HttpServletResponse#SC_NOT_IMPLEMENTED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action NOT_IMPLEMENTED = new SendError(HttpServletResponse.SC_NOT_IMPLEMENTED);

			/**
			 * @see  HttpServletResponse#SC_BAD_GATEWAY
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action BAD_GATEWAY = new SendError(HttpServletResponse.SC_BAD_GATEWAY);

			/**
			 * @see  HttpServletResponse#SC_SERVICE_UNAVAILABLE
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action SERVICE_UNAVAILABLE = new SendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);

			/**
			 * @see  HttpServletResponse#SC_GATEWAY_TIMEOUT
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action GATEWAY_TIMEOUT = new SendError(HttpServletResponse.SC_GATEWAY_TIMEOUT);

			/**
			 * @see  HttpServletResponse#SC_HTTP_VERSION_NOT_SUPPORTED
			 *
			 * @return  Returns {@link Action.Result#TERMINATE} always
			 */
			public static final Action HTTP_VERSION_NOT_SUPPORTED = new SendError(HttpServletResponse.SC_HTTP_VERSION_NOT_SUPPORTED);
		}

		// TODO: sendRedirect

		// </editor-fold>
	}
	// </editor-fold>

	// TODO: Cookies outside request/response?

	// TODO: Session outwise request/response?

	// TODO: javax.servlet.descriptor package?

	// TODO: AO-include/forward args?
}
