package org.keycloak.protocol.docker.installation;

import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.protocol.docker.DockerAuthV2Protocol;
import org.keycloak.protocol.docker.installation.quickstart.DockerComposeZipContent;

import javax.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DockerQuickstartInstallationProvider implements ClientInstallationProvider {
    public static final String QUICKSTART_ROOT_DIR = "docker-registry-quickstart/";

    @Override
    public ClientInstallationProvider create(final KeycloakSession session) {
        return this;
    }

    @Override
    public void init(final Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return "docker-v2-registry-quickstart";
    }

    @Override
    public Response generateInstallation(final KeycloakSession session, final RealmModel realm, final ClientModel client, final URI serverBaseUri) {
        final ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        final ZipOutputStream zipOutput = new ZipOutputStream(byteStream);

        try {
            // TODO if this works, also change other providers to use this instead of the base url and adding 'auth'
            return generateInstallation(zipOutput, byteStream, session.keys().getActiveKey(realm).getCertificate(), session.getContext().getAuthServerUrl().toURL(), realm.getName(), client.getClientId());
        } catch (final IOException e) {
            try {
                zipOutput.close();
            } catch (final IOException ex) {
                // do nothing, already in an exception
            }
            try {
                byteStream.close();
            } catch (final IOException ex) {
                // do nothing, already in an exception
            }
            throw new RuntimeException("Error occurred during attempt to generate Docker quickstart installation files", e);
        }
    }

    public Response generateInstallation(final ZipOutputStream zipOutput, final ByteArrayOutputStream byteStream, final Certificate realmCert, final URL realmBaseURl,
                                         final String realmName, final String clientName) throws IOException {
        final DockerComposeZipContent zipContent = new DockerComposeZipContent(realmCert, realmBaseURl, realmName, clientName);

        zipOutput.putNextEntry(new ZipEntry(QUICKSTART_ROOT_DIR));

        // Write docker compose file
        zipOutput.putNextEntry(new ZipEntry(QUICKSTART_ROOT_DIR + "docker-compose.yaml"));
        zipOutput.write(zipContent.getYamlFile().generateDockerComposeFileBytes());
        zipOutput.closeEntry();

        // Write data directory
        zipOutput.putNextEntry(new ZipEntry(QUICKSTART_ROOT_DIR + zipContent.getDataDirectoryName() + "/"));
        zipOutput.putNextEntry(new ZipEntry(QUICKSTART_ROOT_DIR + zipContent.getDataDirectoryName() + "/.gitignore"));
        zipOutput.write("*".getBytes());
        zipOutput.closeEntry();

        // Write certificates
        final String certsDirectory = QUICKSTART_ROOT_DIR + zipContent.getCertsDirectory().getDirectoryName() + "/";
        zipOutput.putNextEntry(new ZipEntry(certsDirectory));
        zipOutput.putNextEntry(new ZipEntry(certsDirectory + zipContent.getCertsDirectory().getLocalhostCertFile().getKey()));
        zipOutput.write(zipContent.getCertsDirectory().getLocalhostCertFile().getValue());
        zipOutput.closeEntry();
        zipOutput.putNextEntry(new ZipEntry(certsDirectory + zipContent.getCertsDirectory().getLocalhostKeyFile().getKey()));
        zipOutput.write(zipContent.getCertsDirectory().getLocalhostKeyFile().getValue());
        zipOutput.closeEntry();
        zipOutput.putNextEntry(new ZipEntry(certsDirectory + zipContent.getCertsDirectory().getIdpTrustChainFile().getKey()));
        zipOutput.write(zipContent.getCertsDirectory().getIdpTrustChainFile().getValue());
        zipOutput.closeEntry();

        zipOutput.close();
        byteStream.close();

        return Response.ok(byteStream.toByteArray(), getMediaType()).build();
    }

    @Override
    public String getProtocol() {
        return DockerAuthV2Protocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getDisplayType() {
        return "Quickstart";
    }

    @Override
    public String getHelpText() {
        return "Produces a zip file that can be used to stand up a development registry on localhost";
    }

    @Override
    public String getFilename() {
        return "registry-quickstart.zip";
    }

    @Override
    public String getMediaType() {
        return "application/zip";
    }

    @Override
    public boolean isDownloadOnly() {
        return true;
    }
}
