package dev.saathi.personal.network;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;

import dev.saathi.model.ScanVerdict;
import dev.saathi.personal.R;
import dev.saathi.personal.data.db.ScanRecord;
import dev.saathi.personal.data.db.SecurityAuditRepository;
import dev.saathi.personal.ui.MainActivity;
import dev.saathi.personal.ui.state.AppState;
import dev.saathi.shield.network.DnsPacketBuilder;
import dev.saathi.shield.network.DnsPacketParser;
import dev.saathi.shield.network.LocalFirewallEngine;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Real Android VpnService implementation providing opt-in on-device DNS protection.
 *
 * TECHNICAL SCOPE & ARCHITECTURAL BOUNDARIES:
 * - Operates strictly at Layer 3/4 DNS level (port 53 UDP).
 * - Does NOT intercept or decrypt HTTPS application traffic.
 * - Does NOT install custom CA certificates or perform man-in-the-middle decryption.
 * - Does NOT route regular TCP/UDP traffic into a black-hole sink; preserves standard connectivity.
 * - Known malicious domains are sinkholed to 0.0.0.0 locally, preventing connections before they start.
 * - Legitimate domains are forwarded to protected upstream DNS (8.8.8.8 / 1.1.1.1).
 */
public class SaathiVpnService extends VpnService {

    public static final String ACTION_START = "dev.saathi.personal.network.ACTION_START";
    public static final String ACTION_STOP = "dev.saathi.personal.network.ACTION_STOP";

    private static final String CHANNEL_ID = "saathi_network_protection";
    private static final int NOTIFICATION_ID = 2026;

    private static final String VPN_VIRTUAL_GATEWAY = "10.200.0.1";
    private static final String VPN_VIRTUAL_ADDRESS = "10.200.0.2";
    private static final int VPN_PREFIX_LENGTH = 30;
    private static final int VPN_MTU = 1500;

    private static volatile boolean serviceRunning = false;
    private static volatile SaathiVpnService activeInstance = null;

    private ParcelFileDescriptor vpnInterface = null;
    private Thread workerThread = null;
    private volatile boolean isTerminating = false;

    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;
    private final ExecutorService auditExecutor = Executors.newSingleThreadExecutor();

    public static boolean isServiceRunning() {
        return serviceRunning && activeInstance != null && activeInstance.vpnInterface != null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        setupNetworkCallback();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopProtection();
            return START_NOT_STICKY;
        }

        startProtection();
        return START_STICKY;
    }

    private void startProtection() {
        if (serviceRunning) {
            return;
        }

        Notification notification = buildForegroundNotification();
        startForeground(NOTIFICATION_ID, notification);

        try {
            Builder builder = new Builder();
            builder.setSession("Saathi DNS Shield");
            builder.setMtu(VPN_MTU);
            builder.addAddress(VPN_VIRTUAL_ADDRESS, VPN_PREFIX_LENGTH);

            // Bounded routing: ONLY route traffic to the virtual DNS gateway
            // All regular TCP/UDP application traffic bypasses TUN and goes over physical network
            builder.addRoute(VPN_VIRTUAL_GATEWAY, 32);
            builder.addDnsServer(VPN_VIRTUAL_GATEWAY);

            // Disallow Saathi's own package so threat-intel HTTP calls bypass VPN
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException ignored) {}

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                NetworkProtectionManager.getInstance(this).onServiceFailed("System rejected VPN establishment (another VPN may be active)");
                stopForeground(true);
                stopSelf();
                return;
            }

            activeInstance = this;
            serviceRunning = true;
            isTerminating = false;

            NetworkProtectionManager.getInstance(this).onServiceStarted();

            workerThread = new Thread(this::runPacketLoop, "SaathiVpnWorker");
            workerThread.start();

        } catch (Exception e) {
            NetworkProtectionManager.getInstance(this).onServiceFailed("VPN init failed: " + e.getMessage());
            stopForeground(true);
            stopSelf();
        }
    }

    private void runPacketLoop() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] packetBuffer = new byte[32768];

        LocalFirewallEngine firewall = AppState.get().getFirewallEngine();

        while (!isTerminating && serviceRunning) {
            try {
                int bytesRead = in.read(packetBuffer);
                if (bytesRead <= 0) {
                    continue;
                }

                DnsPacketParser.ParsedDnsQuery query = DnsPacketParser.parse(packetBuffer, bytesRead);
                if (query == null || !query.isStandardQuery() || query.qName == null) {
                    continue; // Skip malformed or non-DNS packets safely
                }

                boolean shouldBlock = firewall.shouldBlockConnection(query.qName, query.destinationPort);

                if (shouldBlock) {
                    // Local sinkhole response (0.0.0.0 or NXDOMAIN)
                    byte[] sinkholePacket = DnsPacketBuilder.buildSinkholeResponse(query);
                    if (sinkholePacket != null) {
                        out.write(sinkholePacket);
                    }

                    // Record genuine blocked threat in SQLite audit trail off-thread
                    final String blockedDomain = query.qName;
                    auditExecutor.execute(() -> recordBlockedDomainAudit(blockedDomain));

                } else {
                    // Forward legitimate query to protected upstream DNS
                    forwardQueryUpstream(query, out);
                }

            } catch (IOException e) {
                if (isTerminating) {
                    break;
                }
                // Handle socket / file descriptor read issues safely
            } catch (Exception ignored) {}
        }
    }

    private void forwardQueryUpstream(DnsPacketParser.ParsedDnsQuery query, FileOutputStream out) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            // Protect socket so its outbound packets bypass this VPN tunnel
            protect(socket);
            socket.setSoTimeout(2500);

            InetAddress upstreamDns = InetAddress.getByName("8.8.8.8");
            DatagramPacket outPacket = new DatagramPacket(
                    query.rawDnsPayload,
                    query.rawDnsPayload.length,
                    upstreamDns,
                    53
            );
            socket.send(outPacket);

            byte[] responseBuffer = new byte[4096];
            DatagramPacket inPacket = new DatagramPacket(responseBuffer, responseBuffer.length);
            socket.receive(inPacket);

            byte[] clientPacket = DnsPacketBuilder.buildForwardedResponse(
                    query,
                    inPacket.getData(),
                    inPacket.getLength()
            );

            if (clientPacket != null) {
                out.write(clientPacket);
            }

        } catch (SocketTimeoutException ignored) {
            // Upstream timeout: drop packet or let client retry safely
        } catch (Exception ignored) {
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private void recordBlockedDomainAudit(String domain) {
        try {
            SecurityAuditRepository repo = AppState.get().getAuditRepository();
            if (repo != null) {
                String scanId = "fw-" + System.currentTimeMillis();
                ScanRecord record = new ScanRecord(
                        scanId,
                        "NETWORK_FIREWALL",
                        System.currentTimeMillis(),
                        "COMPLETED",
                        "Blocked on-device connection to malicious domain: " + domain,
                        domain,
                        "1.0.0",
                        true,
                        "KNOWN_MALICIOUS",
                        "CRITICAL",
                        "Sinkholed by local DNS firewall before connection could start"
                );
                repo.insertScan(record, java.util.Collections.emptyList(), null);
            }
        } catch (Exception ignored) {}
    }

    private void stopProtection() {
        isTerminating = true;
        serviceRunning = false;

        if (workerThread != null) {
            workerThread.interrupt();
            workerThread = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException ignored) {}
            vpnInterface = null;
        }

        activeInstance = null;
        NetworkProtectionManager.getInstance(this).onServiceStopped();

        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopProtection();
        if (connectivityManager != null && networkCallback != null) {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback);
            } catch (Exception ignored) {}
        }
        super.onDestroy();
    }

    private void setupNetworkCallback() {
        connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) return;

        NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build();

        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                setUnderlyingNetworks(new Network[]{network});
            }

            @Override
            public void onLost(Network network) {
                setUnderlyingNetworks(null);
            }
        };

        try {
            connectivityManager.registerNetworkCallback(request, networkCallback);
        } catch (Exception ignored) {}
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Network Protection",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Active status for on-device DNS firewall");
            channel.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildForegroundNotification() {
        Intent openIntent = new Intent(this, MainActivity.class);
        PendingIntent piOpen = PendingIntent.getActivity(
                this,
                0,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Intent stopIntent = new Intent(this, SaathiVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent piStop = PendingIntent.getService(
                this,
                1,
                stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Intent settingsIntent;
        try {
            settingsIntent = new Intent(Settings.ACTION_VPN_SETTINGS);
        } catch (Exception e) {
            settingsIntent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        }
        PendingIntent piSettings = PendingIntent.getActivity(
                this,
                2,
                settingsIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        builder.setContentTitle("Saathi Network Protection Active")
                .setContentText("Local DNS firewall filtering malicious domains on-device.")
                .setSmallIcon(R.drawable.ic_nav_scan)
                .setContentIntent(piOpen)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_delete, "Stop Protection", piStop)
                .addAction(android.R.drawable.ic_menu_preferences, "VPN Settings", piSettings);

        return builder.build();
    }
}
