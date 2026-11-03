package com.chiffrium.infrastructure.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;

/**
 * Restreint un fichier sensible à son propriétaire, sous Linux (permissions POSIX 600/700) comme sous
 * Windows (ACL limitée au compte courant).
 */
public final class SecureFiles {

    private static final Logger LOG = LoggerFactory.getLogger(SecureFiles.class);

    private SecureFiles() {
    }

    public static void restrictToOwner(Path path) {
        try {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(
                        Files.isDirectory(path) ? "rwx------" : "rw-------"));
                return;
            }
            AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (acl != null) {
                UserPrincipal owner = Files.getOwner(path);
                AclEntry entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                        .build();
                acl.setAcl(List.of(entry));
            }
        } catch (IOException | UnsupportedOperationException e) {
            LOG.warn("Impossible de restreindre les droits de {} : protéger le dossier de données manuellement", path, e);
        }
    }
}
