package hudson.plugins.ec2.ssh;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.KeyPair;
import com.trilead.ssh2.HTTPProxyData;
import com.trilead.ssh2.ServerHostKeyVerifier;
import hudson.ProxyConfiguration;
import hudson.model.TaskListener;
import hudson.plugins.ec2.*;
import hudson.plugins.ec2.ssh.verifiers.HostKey;
import hudson.plugins.ec2.ssh.verifiers.Messages;
import hudson.plugins.ec2.util.LogHelper;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;

public class SshHelper {
    private final static LogHelper logHelper = new LogHelper(SshHelper.class.getName());

    private static int bootstrapAuthSleepMs = 30000;
    private static int bootstrapAuthTries = 30;


    public static RemoteSshConnection connectToSsh(EC2Computer computer, TaskListener listener, SlaveTemplate template, SshCredential credential) throws AmazonClientException,
            InterruptedException, RemoteSshConnection.AuthenticationException {
        final EC2AbstractSlave node = computer.getNode();
        final long timeout = node == null ? 0L : node.getLaunchTimeoutInMillis();
        final long startTime = System.currentTimeMillis();
        while (true) {
            try {
                long waitTime = System.currentTimeMillis() - startTime;
                if (timeout > 0 && waitTime > timeout) {
                    throw new AmazonClientException("Timed out after " + (waitTime / 1000)
                            + " seconds of waiting for ssh to become available. (maximum timeout configured is "
                            + (timeout / 1000) + ")");
                }
                String host = getEC2HostAddress(computer, template);

                if ((node instanceof EC2SpotSlave) && computer.getInstanceId() == null) {
                    // getInstanceId() on EC2SpotSlave can return null if the spot request doesn't yet know
                    // the instance id that it is starting. Continue to wait until the instanceId is set.
                    logHelper.logInfo(computer, listener, "empty instanceId for Spot Slave.");
                    throw new IOException("goto sleep");
                }

                if ("0.0.0.0".equals(host)) {
                    logHelper.logWarning(computer, listener, "Invalid host 0.0.0.0, your host is most likely waiting for an ip address.");
                    throw new IOException("goto sleep");
                }

                int port = computer.getSshPort();
                Integer slaveConnectTimeout = Integer.getInteger("jenkins.ec2.slaveConnectTimeout", 10000);
                logHelper.logInfo(computer, listener, "Connecting to " + host + " on port " + port + ", with timeout " + slaveConnectTimeout
                        + ".");
                ProxyConfiguration proxyConfig = Jenkins.get().proxy;
                Proxy proxy = proxyConfig == null ? Proxy.NO_PROXY : proxyConfig.createProxy(host);
                HTTPProxyData proxyData = null;
                if (!proxy.equals(Proxy.NO_PROXY) && proxy.address() instanceof InetSocketAddress) {
                    InetSocketAddress address = (InetSocketAddress) proxy.address();
                    if (null != proxyConfig.getUserName()) {
                        proxyData = new HTTPProxyData(address.getHostName(), address.getPort(), proxyConfig.getUserName(), proxyConfig.getPassword());
                    } else {
                        proxyData = new HTTPProxyData(address.getHostName(), address.getPort());
                    }
                    logHelper.logInfo(computer, listener, "Using HTTP Proxy Configuration");
                }
                RemoteSshConnection conn = null;
                if(credential.key != null){
                    conn = RemoteSshConnection.getPubkeyAuthenticatedClient(host,port,proxyData,new SshHelper.ServerHostKeyVerifierImpl(computer,listener),slaveConnectTimeout,slaveConnectTimeout,credential.username, credential.key);
                }else {
                    conn = RemoteSshConnection.getPasswordAuthenticatedClient(host, port, proxyData, new SshHelper.ServerHostKeyVerifierImpl(computer, listener), slaveConnectTimeout, slaveConnectTimeout, credential.username,credential.password);
                }
                logHelper.logInfo(computer, listener, "Connected via SSH.");
                return conn; // successfully connected
            } catch (IOException e) {
                // keep retrying until SSH comes up
                logHelper.logInfo(computer, listener, "Failed to connect via ssh: " + e.getMessage());

                // If the computer was set offline because it's not trusted, we avoid persisting in connecting to it.
                // The computer is offline for a long period
                if (computer.isOffline() && StringUtils.isNotBlank(computer.getOfflineCauseReason()) && computer.getOfflineCauseReason().equals(Messages.OfflineCause_SSHKeyCheckFailed())) {
                    throw new AmazonClientException("The connection couldn't be established and the computer is now offline", e);
                } else {
                    logHelper.logInfo(computer, listener, "Waiting for SSH to come up. Sleeping 5.");
                    Thread.sleep(5000);
                }
            }
        }
    }

    public static boolean bootstrap(EC2Computer computer, TaskListener listener, SlaveTemplate template) throws IOException,
            InterruptedException, AmazonClientException {
        logHelper.logInfo(computer, listener, "bootstrap()");
        RemoteSshConnection bootstrapConn = null;
        try {
            int tries = bootstrapAuthTries;
            boolean isAuthenticated = false;
            logHelper.logInfo(computer, listener, "Getting keypair...");
            KeyPair key = computer.getCloud().getKeyPair();
            logHelper.logInfo(computer, listener,
                    String.format("Using private key %s (SHA-1 fingerprint %s)", key.getKeyName(), key.getKeyFingerprint()));
            while (tries-- > 0) {
                logHelper.logInfo(computer, listener, "Authenticating as " + computer.getRemoteAdmin());
                try {
                    bootstrapConn = SshHelper.connectToSsh(computer, listener, template,new SshCredential(computer.getRemoteAdmin(), computer.getNode().getAdminPassword().getPlainText(),null));
                    isAuthenticated = true;
                } catch (RemoteSshConnection.AuthenticationException e) {
                    logHelper.logWarning(computer, listener, "Authentication failed. Trying again...");
                    Thread.sleep(bootstrapAuthSleepMs);
                }
            }
            if (!isAuthenticated) {
                logHelper.logWarning(computer, listener, "Authentication failed");
                return false;
            }
        } finally {
            if (bootstrapConn != null) {
                bootstrapConn.close();
            }
        }
        return true;
    }


    /**
     * Our host key verifier just pick up the right strategy and call its verify method.
     */
    private static class ServerHostKeyVerifierImpl implements ServerHostKeyVerifier {

        private final EC2Computer computer;
        private final TaskListener listener;

        public ServerHostKeyVerifierImpl(final EC2Computer computer, final TaskListener listener) {
            this.computer = computer;
            this.listener = listener;
        }

        @Override
        public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) throws Exception {
            SlaveTemplate template = computer.getSlaveTemplate();
            return template != null && template.getHostKeyVerificationStrategy().getStrategy().verify(computer, new HostKey(serverHostKeyAlgorithm, serverHostKey), listener);
        }
    }

    public static String getEC2HostAddress (EC2Computer computer, SlaveTemplate template) throws
            InterruptedException {
        Instance instance = computer.updateInstanceDescription();
        ConnectionStrategy strategy = template.connectionStrategy;
        return EC2HostAddressProvider.unix(instance, strategy);
    }

}
