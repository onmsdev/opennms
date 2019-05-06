/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2016-2016 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2016 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.web.outage.filter;

import org.opennms.web.filter.EqualsFilter;
import org.opennms.web.filter.SQLType;

public class LocationFilter extends EqualsFilter<String> {
    public static final String TYPE = "location";
    private String m_location;

    public LocationFilter(String location) {
        super(TYPE, SQLType.STRING, "NODE.LOCATION", "node.location.locationName", location);
        m_location = location;
    }

    @Override
    public String getTextDescription() {
        return ("location=" + m_location);
    }

    @Override
    public String toString() {
        return ("<LocationFilter: " + this.getDescription() + ">");
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) return false;
        if (!(obj instanceof LocationFilter)) return false;
        return (this.toString().equals(obj.toString()));
    }
}
