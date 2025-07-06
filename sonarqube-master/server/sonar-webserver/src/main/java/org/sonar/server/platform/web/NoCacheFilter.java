/*
 * SonarQube
 * Copyright (C) 2009-2025 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.server.platform.web;

import org.sonar.api.server.http.HttpRequest;
import org.sonar.api.server.http.HttpResponse;
import org.sonar.api.web.FilterChain;
import org.sonar.api.web.HttpFilter;
import java.io.IOException;
import org.sonar.api.web.UrlPattern;

public class NoCacheFilter extends HttpFilter {

  @Override
  public void doFilter(HttpRequest httpRequest, HttpResponse httpResponse, FilterChain filterChain) throws IOException {
    httpResponse.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    filterChain.doFilter(httpRequest, httpResponse);
  }

  /**
   * The Cache-Control for API v1 is handled in the org.sonar.server.ws.ServletResponse
   */
  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.builder()
      .includes("/api/v2/*")
      .build();
  }
}
