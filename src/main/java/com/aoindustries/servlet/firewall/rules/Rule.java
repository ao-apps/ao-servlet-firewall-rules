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

/**
 * A rule is zero or more {@link Matcher matchers},
 * for which zero or more {@link Action actions} will be taken, until the first terminating action that returns
 * {@code true} from {@link Action#perform(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain, com.aoindustries.net.pathspace.Prefix, com.aoindustries.net.Path, com.aoindustries.net.Path)}.
 */
public interface Rule {

	/**
	 * Gets that matchers for this rule.
	 * All must {@link Matcher#matches(javax.servlet.http.HttpServletRequest, com.aoindustries.net.pathspace.Prefix, com.aoindustries.net.Path, com.aoindustries.net.Path) match}
	 * for this rule to be used.
	 * If empty, is considered a match.
	 */
	Iterable<? extends Matcher> getMatchers();

	/**
	 * Gets the actions for this rule.  If empty, no action is {@link Action#perform(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain, com.aoindustries.net.pathspace.Prefix, com.aoindustries.net.Path, com.aoindustries.net.Path) performed}.
	 * Actions after the first terminating action are not performed.
	 */
	Iterable<? extends Action> getActions();
}
