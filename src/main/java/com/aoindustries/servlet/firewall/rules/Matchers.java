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
import com.aoindustries.net.pathspace.PathSpace.PathMatch;
import com.aoindustries.servlet.firewall.api.Action;
import com.aoindustries.servlet.firewall.api.FirewallContext;
import com.aoindustries.servlet.firewall.api.Matcher;
import com.aoindustries.servlet.firewall.api.Matcher.Result;
import com.aoindustries.servlet.firewall.api.Rule;
import com.aoindustries.servlet.http.ServletUtil;
import com.aoindustries.util.AoCollections;
import com.aoindustries.util.WildcardPatternMatcher;
import com.aoindustries.validation.ValidationException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.regex.Pattern;
import javax.servlet.DispatcherType;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

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
		public Result perform(FirewallContext context, HttpServletRequest request) {
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
		public Result perform(FirewallContext context, HttpServletRequest request) {
			return Result.MATCH;
		}
	};

	/**
	 * Matches when all matchers match.
	 * Stops processing {@code rules} (both matchers and actions) when the first matcher does not match.
	 * Performs any actions while processing rules, up to the point stopped on first non-matching matcher.
	 *
	 * @return  {@link Result#MATCH} when rules is empty
	 */
	public static Matcher all(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						Result result = context.call((Matcher)rule);
						switch(result) {
							case TERMINATE :
								return Result.TERMINATE;
							case NO_MATCH :
								return Result.NO_MATCH;
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
								return Result.TERMINATE;
							case CONTINUE :
								break;
							default :
								throw new AssertionError();
						}
					}
				}
				return Result.MATCH;
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
	 * @return  {@link Result#MATCH} when rules is empty
	 */
	public static Matcher all(final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
		return new Matcher() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				boolean matched = true;
				RULES :
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						Result result = context.call((Matcher)rule);
						switch(result) {
							case TERMINATE :
								return Result.TERMINATE;
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
								return Result.TERMINATE;
							case CONTINUE :
								// Continue to next rule
								break;
							default :
								throw new AssertionError();
						}
					}
				}
				if(matched) {
					return Result.MATCH;
				} else {
					return callRules(context, otherwise, Result.NO_MATCH);
				}
			}
		};
	}

	public static Matcher all(Rule ... rules) {
		if(rules.length == 0) return all;
		return all(Arrays.asList(rules));
	}

	public static Matcher all(Rule[] rules, Rule ... otherwise) {
		if(otherwise.length == 0) return all(rules);
		return all(Arrays.asList(rules), Arrays.asList(otherwise));
	}

	/**
	 * Matches when any matchers match.
	 * Stops processing matchers once the first match is found.
	 * Begins processing actions once the first match is found.
	 *
	 * @return  {@link Result#NO_MATCH} when rules is empty
	 *
	 * @see  #none
	 */
	public static Matcher any(final Iterable<? extends Rule> rules) {
		return new Matcher() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				boolean matched = false;
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						if(!matched) {
							Result result = context.call((Matcher)rule);
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
									throw new AssertionError();
							}
						}
					}
					if(rule instanceof Action) {
						if(matched) {
							Action.Result result = context.call((Action)rule);
							switch(result) {
								case TERMINATE :
									return Result.TERMINATE;
								case CONTINUE :
									// Continue with any additional actions
									break;
								default :
									throw new AssertionError();
							}
						}
					}
				}
				return matched ? Result.MATCH : Result.NO_MATCH;
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
	 * @return  {@link Result#NO_MATCH} when rules is empty
	 *
	 * @see  #none
	 */
	public static Matcher any(final Iterable<? extends Rule> rules, final Iterable<? extends Rule> otherwise) {
		return new Matcher() {
			@Override
			public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				boolean matched = false;
				for(Rule rule : rules) {
					if(rule instanceof Matcher) {
						if(!matched) {
							Result result = context.call((Matcher)rule);
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
									throw new AssertionError();
							}
						}
					}
					if(rule instanceof Action) {
						if(matched) {
							Action.Result result = context.call((Action)rule);
							switch(result) {
								case TERMINATE :
									return Result.TERMINATE;
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
					return Result.MATCH;
				} else {
					return callRules(context, otherwise, Result.NO_MATCH);
				}
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

	public static Matcher any(Rule[] rules, Rule ... otherwise) {
		if(otherwise.length == 0) return any(rules);
		return any(Arrays.asList(rules), Arrays.asList(otherwise));
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
			public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				Result result = context.call(matcher);
				switch(result) {
					case TERMINATE : return Result.TERMINATE;
					case MATCH     : return Result.NO_MATCH;
					case NO_MATCH  : return Result.MATCH;
					default        : throw new AssertionError();
				}
			}
		};
	}

	/**
	 * Shared implementation for when matchers match the request and are dispatching to all their nested rules.
	 * This is also used for "otherwise" when the matcher does not match.
	 */
	private static Result callRules(FirewallContext context, Iterable<? extends Rule> rules, Result result) throws IOException, ServletException {
		for(Rule rule : rules) {
			if(rule instanceof Matcher) {
				Result matcherResult = context.call((Matcher)rule);
				if(matcherResult == Result.TERMINATE) return Result.TERMINATE;
			}
			if(rule instanceof Action) {
				Action.Result actionResult = context.call((Action)rule);
				if(actionResult == Action.Result.TERMINATE) return Result.TERMINATE;
			}
		}
		return result;
	}

	/**
	 * Shared implementation for when matchers match the request and are dispatching to all their nested rules.
	 */
	private static Result doMatches(boolean matches, FirewallContext context, Iterable<? extends Rule> rules) throws IOException, ServletException {
		if(matches) {
			return callRules(context, rules, Result.MATCH);
		} else {
			return Result.NO_MATCH;
		}
	}

	/**
	 * Shared implementation for when matchers match the request and are dispatching to all their nested rules.
	 */
	private static Result doMatches(boolean matches, FirewallContext context, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) throws IOException, ServletException {
		if(matches) {
			return callRules(context, rules, Result.MATCH);
		} else {
			return callRules(context, otherwise, Result.NO_MATCH);
		}
	}
	// </editor-fold>

	// TODO: Registration?
	// TODO: Servlet/HttpServlet/ServletConfig/ServletRegistration anything useful at filter processing stage?

	// TODO: RequestDispatcher (and all associated constants)?

	// <editor-fold defaultstate="collapsed" desc="servletContext">
	/**
	 * @see  ServletContext
	 *
	 * // TODO: Name just "context", but what if we have FirewallContext?
	 */
	public static class servletContext {

		private servletContext() {}

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

	// <editor-fold defaultstate="collapsed" desc="request">
	/**
	 * @see  ServletRequest
	 * @see  HttpServletRequest
	 */
	public static class request {

		private request() {}

		// <editor-fold defaultstate="collapsed" desc="ServletRequest">

		// TODO: AsyncContext (and all associated constants)?

		// TODO: Attributes (allowing to remove/set in non-terminal action?)

		// TODO: getCharacterEncoding?

		// TODO: getContentLength?

		// TODO: getContentType?

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
				public Result perform(FirewallContext context, HttpServletRequest request) {
					return request.getDispatcherType() == dispatcherType
						? Result.MATCH
						: Result.NO_MATCH;
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) {
						DispatcherType type = request.getDispatcherType();
						for(DispatcherType dispatcherType : dispatcherTypes) {
							if(dispatcherType == type) return Result.MATCH;
						}
						return Result.NO_MATCH;
					}
				};
			}

			/**
			 * Matches any of a given set of {@link DispatcherType}.
			 */
			public static Matcher in(final EnumSet<? extends DispatcherType> dispatcherTypes) {
				return new Matcher() {
					@Override
					public Result perform(FirewallContext context, HttpServletRequest request) {
						return dispatcherTypes.contains(request.getDispatcherType())
							? Result.MATCH
							: Result.NO_MATCH;
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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

		// <editor-fold defaultstate="collapsed" desc="authType">
		/**
		 * TODO: Support nulls?
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
				public Result perform(FirewallContext context, HttpServletRequest request) {
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(final String authType, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) {
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
					public Result perform(FirewallContext context, HttpServletRequest request) {
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Iterable<? extends String> authTypes, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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

		// TODO: getContextPath?

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
				public Result perform(FirewallContext context, HttpServletRequest request) {
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher is(final String method, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) {
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
					public Result perform(FirewallContext context, HttpServletRequest request) {
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
			 *
			 * @param  rules  Invoked only when matched.
			 */
			public static Matcher in(final Iterable<? extends String> methods, final Iterable<? extends Rule> rules) {
				return new Matcher() {
					@Override
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
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
					public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
						return doMatches(methods.contains(request.getMethod()), context, rules, otherwise);
					}
				};
			}

			/**
			 * Matches any of a given set of {@link HttpServletRequest#getMethod()}.
			 *
			 * @param  rules  Invoked only when matched.
			 */
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

	// <editor-fold defaultstate="collapsed" desc="pathMatch">
	/**
	 * TODO: Move to own package or to path-space or servlet-space package?
	 *
	 * @see  PathMatch
	 */
	public static class pathMatch {

		private pathMatch() {}

		/**
		 * The request key that holds the current PathMatch.
		 */
		private static final String PATH_MATCH_REQUEST_KEY = pathMatch.class.getName();

		/**
		 * Gets the {@link PathMatch} for the current servlet space.
		 *
		 * @throws ServletException when no {@link PathMatch} set.
		 */
		private static PathMatch<?> getPathMatch(FirewallContext context) throws ServletException {
			PathMatch<?> pathMatch = (PathMatch<?>)context.getAttribute(PATH_MATCH_REQUEST_KEY);
			if(pathMatch == null) throw new ServletException("PathMatch not set on request");
			return pathMatch;
		}

		private abstract static class PathMatchMatcher implements Matcher {
			@Override
			final public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				PathMatch<?> pathMatch = getPathMatch(context);
				if(
					matches(
						context,
						request,
						pathMatch.getPrefix(),
						pathMatch.getPrefixPath(),
						pathMatch.getPath()
					)
				) {
					return Result.MATCH;
				} else {
					return Result.NO_MATCH;
				}
			}

			/**
			 * @param  prefix  See {@link PathMatch#getPrefix()}
			 * @param  prefixPath  See {@link PathMatch#getPrefixPath()}
			 * @param  path  See {@link PathMatch#getPath()}
			 *
			 * @see  #perform(com.aoindustries.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)
			 */
			abstract protected boolean matches(
				FirewallContext context,
				HttpServletRequest request,
				com.aoindustries.net.pathspace.Prefix prefix,
				Path prefixPath,
				Path path
			) throws IOException, ServletException;
		}

		private abstract static class PathMatchMatcherWithRules implements Matcher {

			private final Iterable<? extends Rule> rules;

			private PathMatchMatcherWithRules(Iterable<? extends Rule> rules) {
				this.rules = rules;
			}

			//private PathMatchMatcherWithRules(Rule ... rules) {
			//	this(Arrays.asList(rules));
			//}

			@Override
			final public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				PathMatch<?> pathMatch = getPathMatch(context);
				return doMatches(
					matches(
						context,
						request,
						pathMatch.getPrefix(),
						pathMatch.getPrefixPath(),
						pathMatch.getPath()
					),
					context,
					rules
				);
			}

			/**
			 * @param  prefix  See {@link PathMatch#getPrefix()}
			 * @param  prefixPath  See {@link PathMatch#getPrefixPath()}
			 * @param  path  See {@link PathMatch#getPath()}
			 *
			 * @see  #perform(com.aoindustries.servlet.firewall.rules.FirewallContext, javax.servlet.http.HttpServletRequest)
			 */
			abstract protected boolean matches(
				FirewallContext context,
				HttpServletRequest request,
				com.aoindustries.net.pathspace.Prefix prefix,
				Path prefixPath,
				Path path
			) throws IOException, ServletException;
		}

		private abstract static class PathMatchMatcherWithRulesAndOtherwise implements Matcher {

			private final Iterable<? extends Rule> rules;
			private final Iterable<? extends Rule> otherwise;

			private PathMatchMatcherWithRulesAndOtherwise(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				this.rules = rules;
				this.otherwise = otherwise;
			}

			//private PathMatchMatcherWithRulesAndOtherwise(Rule[] rules, Rule ... otherwise) {
			//	this(Arrays.asList(rules), Arrays.asList(otherwise));
			//}

			@Override
			final public Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				PathMatch<?> pathMatch = getPathMatch(context);
				return doMatches(
					matches(
						context,
						request,
						pathMatch.getPrefix(),
						pathMatch.getPrefixPath(),
						pathMatch.getPath()
					),
					context,
					rules,
					otherwise
				);
			}

			/**
			 * @param  prefix  See {@link PathMatch#getPrefix()}
			 * @param  prefixPath  See {@link PathMatch#getPrefixPath()}
			 * @param  path  See {@link PathMatch#getPath()}
			 *
			 * @see  #perform(com.aoindustries.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)
			 */
			abstract protected boolean matches(
				FirewallContext context,
				HttpServletRequest request,
				com.aoindustries.net.pathspace.Prefix prefix,
				Path prefixPath,
				Path path
			) throws IOException, ServletException;
		}

		// <editor-fold defaultstate="collapsed" desc="prefix">
		/**
		 * @see  PathMatch#getPrefix()
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return _prefix.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return _prefix.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return _prefix.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return startsWith(prefix, rules);
				return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return _prefix.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return _prefix.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return endsWith(suffix, rules);
				return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return contains(substring, rules);
				return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.pathspace.Prefix target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.pathspace.Prefix target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(final com.aoindustries.net.pathspace.Prefix target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
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
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#equals(java.lang.Object)
			 */
			public static Matcher equals(com.aoindustries.net.pathspace.Prefix target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
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
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target), rules);
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target), rules, otherwise);
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target), rules);
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  com.aoindustries.net.pathspace.Prefix#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(com.aoindustries.net.pathspace.Prefix.valueOf(target), rules, otherwise);
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefix.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equalsIgnoreCase(target, rules);
				return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
					   return pattern.matcher(prefix.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(prefix.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(prefix.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(pattern, rules);
				return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(prefix.toString());
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(prefix.toString());
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(prefix.toString());
					}
				};
			}

			/**
			 * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(wildcardPattern, rules);
				return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
			}
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="prefixPath">
		/**
		 * @see  PathMatch#getPrefixPath()
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return prefixPath.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return prefixPath.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return prefixPath.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return startsWith(prefix, rules);
				return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return endsWith(suffix, rules);
				return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return contains(substring, rules);
				return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.equals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(Path target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(Path target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target) {
				try {
					return equals(Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				try {
					return equals(Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				try {
					return equals(Path.valueOf(target), rules, otherwise);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				try {
					return equals(Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
				try {
					return equals(Path.valueOf(target), rules, otherwise);
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return prefixPath.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equalsIgnoreCase(target, rules);
				return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(prefixPath.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(prefixPath.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(prefixPath.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(pattern, rules);
				return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(prefixPath.toString());
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(prefixPath.toString());
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(prefixPath.toString());
					}
				};
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}

			/**
			 * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(wildcardPattern, rules);
				return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
			}
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="path">
		/**
		 * @see  PathMatch#getPath()
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return path.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return path.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix _prefix, Path prefixPath, Path path) {
						return path.toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return startsWith(prefix, rules);
				return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return endsWith(suffix, rules);
				return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return contains(substring, rules);
				return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.equals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.equals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.equals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(Path target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(Path target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target) {
				try {
					return equals(Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				try {
					return equals(Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				try {
					return equals(Path.valueOf(target), rules, otherwise);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				try {
					return equals(Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when a request path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
				try {
					return equals(Path.valueOf(target), rules, otherwise);
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new PathMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return path.toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equalsIgnoreCase(target, rules);
				return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(path.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(path.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return pattern.matcher(path.toString()).matches();
					}
				};
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(pattern, rules);
				return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
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
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(path.toString());
					}
				};
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
				return new PathMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(path.toString());
					}
				};
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, com.aoindustries.net.pathspace.Prefix prefix, Path prefixPath, Path path) {
						return wildcardPattern.isMatch(path.toString());
					}
				};
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}

			/**
			 * Matches when a request path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(wildcardPattern, rules);
				return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
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
