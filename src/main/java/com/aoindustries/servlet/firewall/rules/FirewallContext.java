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
import javax.servlet.ServletException;

/**
 * Invocation of {@link Rule rules} must be done through the firewall context.
 * This is done to support firewall hooks, such as TRACE.
 */
public interface FirewallContext {

	Matcher.Result call(Matcher matcher) throws IOException, ServletException;

	Action.Result call(Action action) throws IOException, ServletException;

	// TODO: A way to wrap request/response while calling a callable, useful for noSession but while ensuring
	//       original request/response left in-tact.
}
