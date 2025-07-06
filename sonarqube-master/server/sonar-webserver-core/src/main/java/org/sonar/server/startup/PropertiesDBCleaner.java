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
package org.sonar.server.startup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarRuntime;
import org.sonar.api.Startable;
import org.sonar.db.DbClient;
import org.sonar.db.DbSession;

import static java.util.Arrays.asList;

public class PropertiesDBCleaner implements Startable {
  private static final Logger LOG = LoggerFactory.getLogger(PropertiesDBCleaner.class);
  private final SonarRuntime runtime;
  private final DbClient dbClient;

  public PropertiesDBCleaner(DbClient dbClient, SonarRuntime runtime) {
    this.dbClient = dbClient;
    this.runtime = runtime;
  }

  @Override
  public void start() {
    LOG.info("Clean up properties from db");
    deleteMisraPropertyIfRequired();
  }

  private void deleteMisraPropertyIfRequired() {
    String misraProperty = "sonar.earlyAccess.misra.enabled";
    SonarEdition edition = runtime.getEdition();
    try (DbSession dbSession = dbClient.openSession(false)) {
      if (asList(SonarEdition.COMMUNITY, SonarEdition.DEVELOPER).contains(edition)) {
        dbClient.propertiesDao().deleteGlobalProperty(misraProperty, dbSession);
        dbSession.commit();
      }
    }
  }

  @Override
  public void stop() {
    // Nothing to do
  }
}
