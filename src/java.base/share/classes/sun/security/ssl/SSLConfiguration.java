/*
 * Copyright (c) 2018, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.ssl;

import java.security.*;
import java.util.*;
import java.util.function.BiFunction;
import javax.crypto.KeyGenerator;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import sun.security.action.GetIntegerAction;
import sun.security.action.GetPropertyAction;
import sun.security.ssl.SSLExtension.ClientExtensions;
import sun.security.ssl.SSLExtension.ServerExtensions;

import static sun.security.ssl.NamedGroup.NamedGroupSpec.NAMED_GROUP_NONE;

/**
 * SSL/(D)TLS configuration.
 */
final class SSLConfiguration implements Cloneable {
    // configurations with SSLParameters
    AlgorithmConstraints        userSpecifiedAlgorithmConstraints;
    private List<ProtocolVersion>       enabledProtocols;
    private List<CipherSuite>           enabledCipherSuites;
    ClientAuthType              clientAuthType;
    String                      identificationProtocol;
    List<SNIServerName>         serverNames;
    Collection<SNIMatcher>      sniMatchers;
    String[]                    applicationProtocols;
    boolean                     preferLocalCipherSuites;
    boolean                     enableRetransmissions;
    int                         maximumPacketSize;
    List<ProtocolVersion>       activeProtocols;
    List<CipherSuite>           activeCipherSuites;
    AlgorithmConstraints        algorithmConstraints;

    // The configured signature schemes for "signature_algorithms" and
    // "signature_algorithms_cert" extensions
    List<SignatureScheme>       signatureSchemes;

    // the maximum protocol version of enabled protocols
    ProtocolVersion             maximumProtocolVersion;

    // Configurations per SSLSocket or SSLEngine instance.
    boolean                     isClientMode;
    boolean                     enableSessionCreation;

    // the application layer protocol negotiation configuration
    BiFunction<SSLSocket, List<String>, String> socketAPSelector;
    BiFunction<SSLEngine, List<String>, String> engineAPSelector;

    @SuppressWarnings("removal")
    HashMap<HandshakeCompletedListener, AccessControlContext>
                                handshakeListeners;

    boolean                     noSniExtension;
    boolean                     noSniMatcher;

    // To switch off the extended_master_secret extension.
    static final boolean useExtendedMasterSecret;

    // Allow session resumption without Extended Master Secret extension.
    static final boolean allowLegacyResumption =
        Utilities.getBooleanProperty("jdk.tls.allowLegacyResumption", true);

    // Allow full handshake without Extended Master Secret extension.
    static final boolean allowLegacyMasterSecret =
        Utilities.getBooleanProperty("jdk.tls.allowLegacyMasterSecret", true);

    // Allow full handshake without Extended Master Secret extension.
    static final boolean useCompatibilityMode = Utilities.getBooleanProperty(
            "jdk.tls.client.useCompatibilityMode", true);

    // Respond a close_notify alert if receiving close_notify alert.
    static final boolean acknowledgeCloseNotify  = Utilities.getBooleanProperty(
            "jdk.tls.acknowledgeCloseNotify", false);

    // Set the max size limit for Handshake Message to 2^15
    static final int maxHandshakeMessageSize = GetIntegerAction.privilegedGetProperty(
            "jdk.tls.maxHandshakeMessageSize", 32768);

    // Set the max certificate chain length to 10
    static final int maxCertificateChainLength = GetIntegerAction.privilegedGetProperty(
            "jdk.tls.maxCertificateChainLength", 10);

    // Is the extended_master_secret extension supported?
    static {
        boolean supportExtendedMasterSecret = Utilities.getBooleanProperty(
                    "jdk.tls.useExtendedMasterSecret", true);
        if (supportExtendedMasterSecret) {
            try {
                KeyGenerator.getInstance("SunTlsExtendedMasterSecret");
            } catch (NoSuchAlgorithmException nae) {
                supportExtendedMasterSecret = false;
            }
        }
        useExtendedMasterSecret = supportExtendedMasterSecret;
    }

    SSLConfiguration(SSLContextImpl sslContext, boolean isClientMode) {

        // Configurations with SSLParameters, default values.
        this.userSpecifiedAlgorithmConstraints =
                SSLAlgorithmConstraints.DEFAULT;
        this.enabledProtocols =
                sslContext.getDefaultProtocolVersions(!isClientMode);
        this.enabledCipherSuites =
                sslContext.getDefaultCipherSuites(!isClientMode);
        this.clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;

        this.identificationProtocol = null;
        this.serverNames = Collections.emptyList();
        this.sniMatchers = Collections.emptyList();
        this.preferLocalCipherSuites = true;

        this.applicationProtocols = new String[0];
        this.enableRetransmissions = sslContext.isDTLS();
        this.maximumPacketSize = 0;         // please reset it explicitly later

        this.signatureSchemes = isClientMode ?
                CustomizedClientSignatureSchemes.signatureSchemes :
                CustomizedServerSignatureSchemes.signatureSchemes;
        this.maximumProtocolVersion = ProtocolVersion.NONE;
        for (ProtocolVersion pv : enabledProtocols) {
            if (pv.compareTo(maximumProtocolVersion) > 0) {
                this.maximumProtocolVersion = pv;
            }
        }

        // Configurations per SSLSocket or SSLEngine instance.
        this.isClientMode = isClientMode;
        this.enableSessionCreation = true;
        this.socketAPSelector = null;
        this.engineAPSelector = null;

        this.handshakeListeners = null;
        this.noSniExtension = false;
        this.noSniMatcher = false;

        this.algorithmConstraints = new SSLAlgorithmConstraints(
                this.userSpecifiedAlgorithmConstraints);
        this.activeProtocols = getActiveProtocols(this.enabledProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
        this.activeCipherSuites = getActiveCipherSuites(this.activeProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
    }

    SSLParameters getSSLParameters() {
        SSLParameters params = new SSLParameters();

        params.setAlgorithmConstraints(this.userSpecifiedAlgorithmConstraints);
        params.setProtocols(ProtocolVersion.toStringArray(enabledProtocols));
        params.setCipherSuites(CipherSuite.namesOf(enabledCipherSuites));
        switch (this.clientAuthType) {
            case CLIENT_AUTH_REQUIRED:
                params.setNeedClientAuth(true);
                break;
            case CLIENT_AUTH_REQUESTED:
                params.setWantClientAuth(true);
                break;
            default:
                params.setWantClientAuth(false);
        }
        params.setEndpointIdentificationAlgorithm(this.identificationProtocol);

        if (serverNames.isEmpty() && !noSniExtension) {
            // 'null' indicates none has been set
            params.setServerNames(null);
        } else {
            params.setServerNames(this.serverNames);
        }

        if (sniMatchers.isEmpty() && !noSniMatcher) {
            // 'null' indicates none has been set
            params.setSNIMatchers(null);
        } else {
            params.setSNIMatchers(this.sniMatchers);
        }

        params.setApplicationProtocols(this.applicationProtocols);
        params.setUseCipherSuitesOrder(this.preferLocalCipherSuites);
        params.setEnableRetransmissions(this.enableRetransmissions);
        params.setMaximumPacketSize(this.maximumPacketSize);

        return params;
    }

    void setSSLParameters(SSLParameters params) {
        AlgorithmConstraints ac = params.getAlgorithmConstraints();
        if (ac != null) {
            this.userSpecifiedAlgorithmConstraints = ac;
        }   // otherwise, use the default value

        String[] sa = params.getCipherSuites();
        if (sa != null) {
            this.enabledCipherSuites = CipherSuite.validValuesOf(sa);
        }   // otherwise, use the default values

        sa = params.getProtocols();
        if (sa != null) {
            this.enabledProtocols = ProtocolVersion.namesOf(sa);

            this.maximumProtocolVersion = ProtocolVersion.NONE;
            for (ProtocolVersion pv : enabledProtocols) {
                if (pv.compareTo(maximumProtocolVersion) > 0) {
                    this.maximumProtocolVersion = pv;
                }
            }
        }   // otherwise, use the default values

        if (params.getNeedClientAuth()) {
            this.clientAuthType = ClientAuthType.CLIENT_AUTH_REQUIRED;
        } else if (params.getWantClientAuth()) {
            this.clientAuthType = ClientAuthType.CLIENT_AUTH_REQUESTED;
        } else {
            this.clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;
        }

        String s = params.getEndpointIdentificationAlgorithm();
        if (s != null) {
            this.identificationProtocol = s;
        }   // otherwise, use the default value

        List<SNIServerName> sniNames = params.getServerNames();
        if (sniNames != null) {
            this.noSniExtension = sniNames.isEmpty();
            this.serverNames = sniNames;
        }   // null if none has been set

        Collection<SNIMatcher> matchers = params.getSNIMatchers();
        if (matchers != null) {
            this.noSniMatcher = matchers.isEmpty();
            this.sniMatchers = matchers;
        }   // null if none has been set

        sa = params.getApplicationProtocols();
        if (sa != null) {
            this.applicationProtocols = sa;
        }   // otherwise, use the default values

        this.preferLocalCipherSuites = params.getUseCipherSuitesOrder();
        this.enableRetransmissions = params.getEnableRetransmissions();
        this.maximumPacketSize = params.getMaximumPacketSize();

        this.algorithmConstraints = new SSLAlgorithmConstraints(
                this.userSpecifiedAlgorithmConstraints);
        this.activeProtocols = getActiveProtocols(this.enabledProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
        this.activeCipherSuites = getActiveCipherSuites(this.activeProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
    }

    // SSLSocket only
    @SuppressWarnings("removal")
    void addHandshakeCompletedListener(
            HandshakeCompletedListener listener) {

        if (handshakeListeners == null) {
            handshakeListeners = new HashMap<>(4);
        }

        handshakeListeners.put(listener, AccessController.getContext());
    }

    // SSLSocket only
    void removeHandshakeCompletedListener(
            HandshakeCompletedListener listener) {

        if (handshakeListeners == null) {
            throw new IllegalArgumentException("no listeners");
        }

        if (handshakeListeners.remove(listener) == null) {
            throw new IllegalArgumentException("listener not registered");
        }

        if (handshakeListeners.isEmpty()) {
            handshakeListeners = null;
        }
    }

    /**
     * Return true if the extension is available.
     */
    boolean isAvailable(SSLExtension extension) {
        for (ProtocolVersion protocolVersion : enabledProtocols) {
            if (extension.isAvailable(protocolVersion)) {
                if (isClientMode ?
                        ClientExtensions.defaults.contains(extension) :
                        ServerExtensions.defaults.contains(extension)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Return true if the extension is available for the specific protocol.
     */
    boolean isAvailable(SSLExtension extension,
            ProtocolVersion protocolVersion) {
        return extension.isAvailable(protocolVersion) &&
                (isClientMode ? ClientExtensions.defaults.contains(extension) :
                                ServerExtensions.defaults.contains(extension));
    }

    /**
     * Get the enabled extensions for the specific handshake message.
     *
     * Used to consume handshake extensions.
     */
    SSLExtension[] getEnabledExtensions(SSLHandshake handshakeType) {
        List<SSLExtension> extensions = new ArrayList<>();
        for (SSLExtension extension : SSLExtension.values()) {
            if (extension.handshakeType == handshakeType) {
                if (isAvailable(extension)) {
                    extensions.add(extension);
                }
            }
        }

        return extensions.toArray(new SSLExtension[0]);
    }

    /**
     * Get the enabled extensions for the specific handshake message, excluding
     * the specified extensions.
     *
     * Used to consume handshake extensions.
     */
    SSLExtension[] getExclusiveExtensions(SSLHandshake handshakeType,
            List<SSLExtension> excluded) {
        List<SSLExtension> extensions = new ArrayList<>();
        for (SSLExtension extension : SSLExtension.values()) {
            if (extension.handshakeType == handshakeType) {
                if (isAvailable(extension) && !excluded.contains(extension)) {
                    extensions.add(extension);
                }
            }
        }

        return extensions.toArray(new SSLExtension[0]);
    }

    /**
     * Get the enabled extensions for the specific handshake message
     * and the specific protocol version.
     *
     * Used to produce handshake extensions after handshake protocol
     * version negotiation.
     */
    SSLExtension[] getEnabledExtensions(
            SSLHandshake handshakeType, ProtocolVersion protocolVersion) {
        return getEnabledExtensions(handshakeType, List.of(protocolVersion));
    }

    /**
     * Get the enabled extensions for the specific handshake message
     * and the specific protocol versions.
     *
     * Used to produce ClientHello extensions before handshake protocol
     * version negotiation.
     */
    SSLExtension[] getEnabledExtensions(
            SSLHandshake handshakeType, List<ProtocolVersion> activeProtocols) {
        List<SSLExtension> extensions = new ArrayList<>();
        for (SSLExtension extension : SSLExtension.values()) {
            if (extension.handshakeType == handshakeType) {
                if (!isAvailable(extension)) {
                    continue;
                }

                for (ProtocolVersion protocolVersion : activeProtocols) {
                    if (extension.isAvailable(protocolVersion)) {
                        extensions.add(extension);
                        break;
                    }
                }
            }
        }

        return extensions.toArray(new SSLExtension[0]);
    }

    void toggleClientMode() {
        this.isClientMode ^= true;

        // reset the signature schemes
        this.signatureSchemes = isClientMode ?
                CustomizedClientSignatureSchemes.signatureSchemes :
                CustomizedServerSignatureSchemes.signatureSchemes;
    }

    @Override
    @SuppressWarnings({"removal","unchecked", "CloneDeclaresCloneNotSupported"})
    public Object clone() {
        // Note that only references to the configurations are copied.
        try {
            SSLConfiguration config = (SSLConfiguration)super.clone();
            if (handshakeListeners != null) {
                config.handshakeListeners =
                    (HashMap<HandshakeCompletedListener, AccessControlContext>)
                            handshakeListeners.clone();
            }

            return config;
        } catch (CloneNotSupportedException cnse) {
            // unlikely
        }

        return null;    // unlikely
    }


    // lazy initialization holder class idiom for static default parameters
    //
    // See Effective Java Second Edition: Item 71.
    private static final class CustomizedClientSignatureSchemes {
        private static final List<SignatureScheme> signatureSchemes =
                getCustomizedSignatureScheme("jdk.tls.client.SignatureSchemes");
    }

    // lazy initialization holder class idiom for static default parameters
    //
    // See Effective Java Second Edition: Item 71.
    private static final class CustomizedServerSignatureSchemes {
        private static final List<SignatureScheme> signatureSchemes =
                getCustomizedSignatureScheme("jdk.tls.server.SignatureSchemes");
    }

    /*
     * Get the customized signature schemes specified by the given
     * system property.
     */
    private static List<SignatureScheme> getCustomizedSignatureScheme(
            String propertyName) {

        String property = GetPropertyAction.privilegedGetProperty(propertyName);
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
            SSLLogger.fine(
                    "System property " + propertyName + " is set to '" +
                    property + "'");
        }
        if (property != null && !property.isEmpty()) {
            // remove double quote marks from beginning/end of the property
            if (property.length() > 1 && property.charAt(0) == '"' &&
                    property.charAt(property.length() - 1) == '"') {
                property = property.substring(1, property.length() - 1);
            }
        }

        if (property != null && !property.isEmpty()) {
            String[] signatureSchemeNames = property.split(",");
            List<SignatureScheme> signatureSchemes =
                        new ArrayList<>(signatureSchemeNames.length);
            for (int i = 0; i < signatureSchemeNames.length; i++) {
                signatureSchemeNames[i] = signatureSchemeNames[i].trim();
                if (signatureSchemeNames[i].isEmpty()) {
                    continue;
                }

                SignatureScheme scheme =
                    SignatureScheme.nameOf(signatureSchemeNames[i]);
                if (scheme != null && scheme.isAvailable) {
                    signatureSchemes.add(scheme);
                } else {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
                        SSLLogger.fine(
                                "The current installed providers do not " +
                                "support signature scheme: " +
                                signatureSchemeNames[i]);
                    }
                }
            }

            return signatureSchemes;
        }

        return Collections.emptyList();
    }

    private static List<ProtocolVersion> getActiveProtocols(
            List<ProtocolVersion> enabledProtocols,
            List<CipherSuite> enabledCipherSuites,
            AlgorithmConstraints algorithmConstraints) {
        boolean enabledSSL20Hello = false;
        ArrayList<ProtocolVersion> protocols = new ArrayList<>(4);
        for (ProtocolVersion protocol : enabledProtocols) {
            if (!enabledSSL20Hello && protocol == ProtocolVersion.SSL20Hello) {
                enabledSSL20Hello = true;
                continue;
            }

            if (!algorithmConstraints.permits(
                    EnumSet.of(CryptoPrimitive.KEY_AGREEMENT),
                    protocol.name, null)) {
                // Ignore disabled protocol.
                continue;
            }

            boolean found = false;
            Map<NamedGroup.NamedGroupSpec, Boolean> cachedStatus =
                    new EnumMap<>(NamedGroup.NamedGroupSpec.class);
            for (CipherSuite suite : enabledCipherSuites) {
                if (suite.isAvailable() && suite.supports(protocol)) {
                    if (isActivatable(suite,
                            algorithmConstraints, cachedStatus)) {
                        protocols.add(protocol);
                        found = true;
                        break;
                    }
                } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine(
                            "Ignore unsupported cipher suite: " + suite +
                                    " for " + protocol.name);
                }
            }

            if (!found && (SSLLogger.isOn) && SSLLogger.isOn("handshake")) {
                SSLLogger.fine(
                        "No available cipher suite for " + protocol.name);
            }
        }

        if (!protocols.isEmpty()) {
            if (enabledSSL20Hello) {
                protocols.add(ProtocolVersion.SSL20Hello);
            }
            Collections.sort(protocols);
        }

        return Collections.unmodifiableList(protocols);
    }

    private static List<CipherSuite> getActiveCipherSuites(
            List<ProtocolVersion> enabledProtocols,
            List<CipherSuite> enabledCipherSuites,
            AlgorithmConstraints algorithmConstraints) {

        List<CipherSuite> suites = new LinkedList<>();
        if (enabledProtocols != null && !enabledProtocols.isEmpty()) {
            Map<NamedGroup.NamedGroupSpec, Boolean> cachedStatus =
                    new EnumMap<>(NamedGroup.NamedGroupSpec.class);
            for (CipherSuite suite : enabledCipherSuites) {
                if (!suite.isAvailable()) {
                    continue;
                }

                boolean isSupported = false;
                for (ProtocolVersion protocol : enabledProtocols) {
                    if (!suite.supports(protocol)) {
                        continue;
                    }
                    if (isActivatable(suite,
                            algorithmConstraints, cachedStatus)) {
                        suites.add(suite);
                        isSupported = true;
                        break;
                    }
                }

                if (!isSupported &&
                        SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.finest(
                            "Ignore unsupported cipher suite: " + suite);
                }
            }
        }

        return Collections.unmodifiableList(suites);
    }

    private static boolean isActivatable(CipherSuite suite,
                                         AlgorithmConstraints algorithmConstraints,
                                         Map<NamedGroup.NamedGroupSpec, Boolean> cachedStatus) {

        if (algorithmConstraints.permits(
                EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), suite.name, null)) {
            if (suite.keyExchange == null) {
                // TLS 1.3, no definition of key exchange in cipher suite.
                return true;
            }

            // Is at least one of the group types available?
            boolean groupAvailable, retval = false;
            NamedGroup.NamedGroupSpec[] groupTypes = suite.keyExchange.groupTypes;
            for (NamedGroup.NamedGroupSpec groupType : groupTypes) {
                if (groupType != NAMED_GROUP_NONE) {
                    Boolean checkedStatus = cachedStatus.get(groupType);
                    if (checkedStatus == null) {
                        groupAvailable = SupportedGroupsExtension.SupportedGroups.isActivatable(
                                algorithmConstraints, groupType);
                        cachedStatus.put(groupType, groupAvailable);

                        if (!groupAvailable &&
                                SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                            SSLLogger.fine(
                                    "No activated named group in " + groupType);
                        }
                    } else {
                        groupAvailable = checkedStatus;
                    }

                    retval |= groupAvailable;
                } else {
                    retval = true;
                }
            }

            if (!retval && SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                SSLLogger.fine("No active named group(s), ignore " + suite);
            }

            return retval;

        } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
            SSLLogger.fine("Ignore disabled cipher suite: " + suite);
        }

        return false;
    }

    List<ProtocolVersion> getEnabledProtocols() {
        return enabledProtocols;
    }

    List<CipherSuite> getEnabledCipherSuites() {
        return enabledCipherSuites;
    }

    void setEnabledProtocols(List<ProtocolVersion> enabledProtocols) {
        this.enabledProtocols = enabledProtocols;
        this.activeProtocols = getActiveProtocols(this.enabledProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
        this.activeCipherSuites = getActiveCipherSuites(this.activeProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);

    }

    void setEnabledCipherSuites(List<CipherSuite> enabledCipherSuites) {
        this.enabledCipherSuites = enabledCipherSuites;
        this.activeProtocols = getActiveProtocols(this.enabledProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
        this.activeCipherSuites = getActiveCipherSuites(this.activeProtocols,
                this.enabledCipherSuites, this.algorithmConstraints);
    }

}
