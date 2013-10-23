/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.manager;

import java.security.AccessControlException;
import java.security.CodeSource;
import java.security.Permission;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Modified to remove JBoss dependencies.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SecurityMessages {
    public static final SecurityMessages access = new SecurityMessages();
    private static final Logger log = Logger.getLogger(SecurityMessages.class.getName());

    private SecurityMessages() {
    }

    private static void log(Level level, String msg, Object...params) {
      log.log(Level.FINE, String.format(msg, params));
    }

    public void accessCheckFailed(Permission permission, CodeSource codeSource, ClassLoader classLoader, String principals) {
      log(Level.FINER, "Permission check failed (permission \"%s\" in code source \"%s\" of \"%s\", principals \"%s\")", permission, codeSource, classLoader, principals);
    }

    public void accessCheckFailed(Permission permission, CodeSource codeSource, ClassLoader classLoader) {
      log(Level.FINER, "Permission check failed (permission \"%s\" in code source \"%s\" of \"%s\")", permission, codeSource, classLoader);
    }

    public AccessControlException accessControlException(Permission permission, Permission permission_) {
      final String msg = String.format("Permission check failed for %s", permission_);
      log(Level.WARNING, msg);
      throw new AccessControlException(msg, permission_);
    }

    public SecurityException secMgrChange() {
      final String msg = "Security manager may not be changed";
      log(Level.WARNING, msg);
      throw new SecurityException(msg);
    }

    public SecurityException unknownContext() {
      final String msg = "Unknown security context type";
      log(Level.WARNING, msg);
      throw new SecurityException(msg);
    }
}
