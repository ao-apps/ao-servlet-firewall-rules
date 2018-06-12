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

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The parent interface of either {@link Matcher} or {@link Action}.  No other
 * sub-interfaces are expected, and no direct implementations of this interface
 * are expected.
 * <p>
 * This is to simplify the implementation of the nesting of matchers and actions.
 * </p>
 */
// TODO: Java 1.8: @Functional
public interface Rule {

	// There is currently no common method between matcher and action, since the
	// rule engine uses its own stacks to dispatch between rules, instead of
	// the Java runtime directly? TODO: This actually how we did it?

	enum Result {
		/**
		 * Indicates no match.
		 * Valid from {@link Matcher} only.
		 */
		NO_MATCH,

		/**
		 * Indicates matched.
		 * Valid from {@link Matcher} only.
		 */
		MATCH,

		/**
		 * Indicates an action has been performed, but it is non-terminal and rule processing must continue.
		 * Valid from {@link Action} only.
		 */
		CONTINUE,

		/**
		 * Indicates that a terminal action has been performed.  Rule processing must stop.
		 * Valid from either {@link Matcher} or {@link Action}, however it must originate only from
		 * an {@link Action} and may be propagated up the stack through {@link Matcher}.
		 * We are favoring this propagation of return over exceptions.
		 */
		TERMINATE
	}

	/**
	 * Called for the rule to be performed.
	 *
	 * @param request  The request being matched
	 *
	 * @param response  The current response
	 *
	 * @param chain  The current filter chain
	 *
	 * @return  The {@link Result result} of the rule, see {@link Result}.
	 */
	// TODO: SkipPageException correct here?
	Result perform(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException;
}
