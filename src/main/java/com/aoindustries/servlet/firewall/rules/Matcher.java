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
import com.aoindustries.net.pathspace.PathSpace;
import com.aoindustries.net.pathspace.Prefix;
import javax.servlet.http.HttpServletRequest;

/**
 * Matches {@link HttpServletRequest servlet requests}.
 *
 * @see  Matchers
 *
 * TODO: Include pathInfo in servletPath regarding path space lookups?
 *
 * TODO: matchers should be in own submodule?
 *
 * TODO: Is this redundant with https://docs.spring.io/spring-security/site/docs/4.2.5.RELEASE/apidocs/org/springframework/security/web/util/matcher/package-summary.html?
 */
public interface Matcher {

	/**
	 * Checks if the given request is matched.
	 *
	 * @param request  The request being matched
	 *
	 * @param prefix  See {@link PathSpace.PathMatch#getPrefix()}
	 *
	 * @param prefixPath  See {@link PathSpace.PathMatch#getPrefixPath()}
	 *
	 * @param path  See {@link PathSpace.PathMatch#getPath()}
	 *
	 * @return {@code true} when the request matches, {@code false} otherwise
	 */
	boolean matches(HttpServletRequest request, Prefix prefix, Path prefixPath, Path path);
}
