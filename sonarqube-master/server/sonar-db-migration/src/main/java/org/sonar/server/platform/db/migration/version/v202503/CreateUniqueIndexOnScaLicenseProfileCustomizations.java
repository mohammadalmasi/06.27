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
package org.sonar.server.platform.db.migration.version.v202503;

import java.sql.Connection;
import java.sql.SQLException;
import org.sonar.db.Database;
import org.sonar.db.DatabaseUtils;
import org.sonar.server.platform.db.migration.sql.CreateIndexBuilder;
import org.sonar.server.platform.db.migration.step.DdlChange;

public class CreateUniqueIndexOnScaLicenseProfileCustomizations extends DdlChange {

  static final String TABLE_NAME = "sca_lic_prof_customs";
  static final String INDEX_NAME = "sca_lic_prof_customs_uniq";
  static final String COLUMN_LICENSE_PROFILE_UUID_NAME = "sca_license_profile_uuid";
  static final String COLUMN_LICENSE_POLICY_ID_NAME = "license_policy_id";

  public CreateUniqueIndexOnScaLicenseProfileCustomizations(Database db) {
    super(db);
  }

  @Override
  public void execute(Context context) throws SQLException {
    try (Connection connection = getDatabase().getDataSource().getConnection()) {
      createIndex(context, connection);
    }
  }

  private void createIndex(Context context, Connection connection) {
    if (!DatabaseUtils.indexExistsIgnoreCase(TABLE_NAME, INDEX_NAME, connection)) {
      context.execute(new CreateIndexBuilder(getDialect())
        .setTable(TABLE_NAME)
        .setName(INDEX_NAME)
        .setUnique(true)
        .addColumn(COLUMN_LICENSE_PROFILE_UUID_NAME, false)
        .addColumn(COLUMN_LICENSE_POLICY_ID_NAME, false)
        .build());
    }
  }
}
