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

import java.util.Objects;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarRuntime;
import org.sonar.db.DbClient;
import org.sonar.db.DbSession;
import org.sonar.db.DbTester;
import org.sonar.db.property.PropertyDto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


class PropertiesDBCleanerTest {
  @RegisterExtension
  public DbTester db = DbTester.create();
  private final DbClient dbClient = db.getDbClient();
  private final DbSession dbSession = db.getSession();
  private final SonarRuntime sonarRuntime = mock(SonarRuntime.class);
  private static final String MISRA_SETTING = "sonar.earlyAccess.misra.enabled";

  @ParameterizedTest
  @ValueSource(strings = { "COMMUNITY", "DEVELOPER" })
  void should_clean_up_misra_prop_when_dev_or_community_edition(String edition) {
    when(sonarRuntime.getEdition()).thenReturn(SonarEdition.valueOf(edition));

    dbClient
      .propertiesDao()
      .saveProperty(dbSession, new PropertyDto()
        .setKey(MISRA_SETTING)
        .setValue("true"), null, null, null, null);
    dbSession.commit();

    new PropertiesDBCleaner(dbClient, sonarRuntime).start();
    assertThat(dbClient.propertiesDao().selectGlobalProperty(MISRA_SETTING)).isNull();
  }

  @ParameterizedTest
  @ValueSource(strings = { "ENTERPRISE", "DATACENTER" })
  void should_not_clean_up_misra_prop_when_enterprise_or_above(String edition) {
    when(sonarRuntime.getEdition()).thenReturn(SonarEdition.valueOf(edition));

    PropertyDto prop = new PropertyDto()
      .setKey(MISRA_SETTING)
      .setValue("true");
    dbClient
      .propertiesDao()
      .saveProperty(dbSession, prop, null, null, null, null);
    dbSession.commit();

    new PropertiesDBCleaner(dbClient, sonarRuntime).start();
    assertThat(Objects.requireNonNull(dbClient.propertiesDao().selectGlobalProperty(MISRA_SETTING)).getValue()).isEqualTo(prop.getValue());
  }
}
