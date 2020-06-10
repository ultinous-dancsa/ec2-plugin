package hudson.plugins.ec2.win;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.ec2.model.GetPasswordDataRequest;
import com.amazonaws.services.ec2.model.GetPasswordDataResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.KeyPair;
import com.trilead.ssh2.*;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.TaskListener;
import hudson.os.WindowsUtil;
import hudson.plugins.ec2.*;
import hudson.plugins.ec2.ssh.EC2UnixLauncher;
import hudson.plugins.ec2.ssh.verifiers.HostKey;
import hudson.plugins.ec2.ssh.verifiers.Messages;
import hudson.plugins.ec2.util.RemoteLongProcess;
import hudson.plugins.ec2.win.winrm.WindowsProcess;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Listener;
import hudson.slaves.ComputerLauncher;
import hudson.slaves.OfflineCause;
import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLException;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EC2WindowsSSHLauncher extends EC2ComputerLauncher {
    private static final String AGENT_JAR = "remoting.jar";

    final long sleepBetweenAttempts = TimeUnit.SECONDS.toMillis(10);
    private static final Logger LOGGER = Logger.getLogger(EC2WindowsSSHLauncher.class.getName());


    protected void log(Level level, EC2Computer computer, TaskListener listener, String message) {
        EC2Cloud.log(LOGGER, level, listener, message);
    }

    protected void logException(EC2Computer computer, TaskListener listener, String message, Throwable exception) {
        EC2Cloud.log(LOGGER, Level.WARNING, listener, message, exception);
    }

    protected void logInfo(EC2Computer computer, TaskListener listener, String message) {
        log(Level.INFO, computer, listener, message);
    }

    protected void logWarning(EC2Computer computer, TaskListener listener, String message) {
        log(Level.WARNING, computer, listener, message);
    }


    @Override
    protected void launchScript(EC2Computer computer, TaskListener listener) throws IOException,
            AmazonClientException, InterruptedException {

        PrintStream logger = listener.getLogger();
        logger.println("Egzeqjúting dancsa's ebédszkript v2");
        EC2AbstractSlave node = computer.getNode();
        if (node == null) {
            logger.println("Unable to fetch node information");
            return;
        }
        final SlaveTemplate template = computer.getSlaveTemplate();
        if (template == null) {
            throw new IOException("Could not find corresponding slave template for " + computer.getDisplayName());
        }
        final RemoteSshConnection conn;
        RemoteSshConnection cleanupConn = null; // java's code path analysis for final


        if(node == null) {
            throw new IllegalStateException();
        }

        if (template == null) {
            throw new IOException("Could not find corresponding slave template for " + computer.getDisplayName());
        }

        if (node instanceof EC2Readiness) {
            EC2Readiness readinessNode = (EC2Readiness) node;
            int tries = readinessTries;

            while (tries-- > 0) {
                if (readinessNode.isReady()) {
                    break;
                }

                logInfo(computer, listener, "Node still not ready. Current status: " + readinessNode.getEc2ReadinessStatus());
                Thread.sleep(readinessSleepMs);
            }

            if (!readinessNode.isReady()) {
                throw new AmazonClientException("Node still not ready, timed out after " + (readinessTries * readinessSleepMs / 1000) + "s with status " + readinessNode.getEc2ReadinessStatus());
            }
        }

        logInfo(computer, listener, "Launching instance: " + node.getInstanceId());


        try {
            boolean isBootstrapped = bootstrap(computer, listener, template);
            if (isBootstrapped) {
                // connect fresh as ROOT
                logInfo(computer, listener, "connect fresh");
                try {
                    cleanupConn = connectToSsh(computer, listener, template, computer.getRemoteAdmin(), computer.getNode().getAdminPassword().getPlainText());
                }
                catch (RemoteSshConnection.AuthenticationException e){
                    logWarning(computer, listener, "Authentication failed");
                    return; // failed to connect
                }
                KeyPair key = computer.getCloud().getKeyPair();
            } else {
                logWarning(computer, listener, "bootstrapresult failed");
                return; // bootstrap closed for us.
            }
            conn = cleanupConn;


            String initScript = node.initScript;
            String tmpDir = (node.tmpDir != null && !node.tmpDir.equals("") ? WindowsUtil.quoteArgument(Util.ensureEndsWith(node.tmpDir,"\\"))
                    : "C:/tmp/");

            logger.println("Creating tmp directory if it does not exist");
            //TODO: errorcheck
            conn.executeProcess("New-Item -ItemType Directory -Force -Path " + tmpDir, logger);


            //TODO: check if init.bat has ben run
            if (initScript != null && initScript.trim().length() > 0) {
                logInfo(computer, listener, "Executing init script");
                conn.writeRemoteFile( tmpDir + ".jenkins-init", initScript.getBytes("UTF-8"));
                conn.executeProcess(tmpDir + "/init.bat", logger);

                logger.println("init script ran? successfully");
            }

            // Always copy so we get the most recent slave.jar
            logInfo(computer, listener, "Copying remoting.jar to: " + tmpDir);
            conn.writeRemoteFile(tmpDir + "remoting.jar", Jenkins.get().getJnlpJars("remoting.jar").readFully());

            logger.println("remoting.jar sent remotely. Bootstrapping it");

            final String jvmopts = node.jvmopts;
            final String remoteFS = WindowsUtil.quoteArgument(node.getRemoteFS());
            final String workDir = Util.fixEmptyAndTrim(remoteFS) != null ? remoteFS : tmpDir;
            final String launchString = "java " + (jvmopts != null ? jvmopts : "") + " -jar " + tmpDir + AGENT_JAR + " -workDir " + workDir;
            logger.println("Launching via WinRM:" + launchString);
            RemoteLongProcess process = conn.runProcess(launchString);
            computer.setChannel(process.getStdout(), process.getStdin(), logger, new Listener() {
                @Override
                public void onClosed(Channel channel, IOException cause) {
                    process.destroy();
                    conn.close();
                }
            });


        } catch (EOFException eof) {
            // When we launch java with connection.execute(launchString... it keeps running, but if java is not installed
            //the computer.setChannel fails with EOFException because the stream is already closed. It fails on
            // setChannel - build - negotiate - is.read() == -1. Let's print a clear message to help diagnose the problem
            // In other case you see a EOFException which gives you few clues about the problem.
            logger.println("The stream with the java process on the instance was closed. Maybe java is not installed there.");
            eof.printStackTrace(logger);
        } catch (Throwable ioe) {
            logger.println("Ouch:");
            ioe.printStackTrace(logger);
        } finally {
            //conn.close(); FIXME
        }
    }


    private static int bootstrapAuthSleepMs = 30000;
    private static int bootstrapAuthTries = 30;

    private static int readinessSleepMs = 1000;
    private static int readinessTries = 120;

    private boolean bootstrap(EC2Computer computer, TaskListener listener, SlaveTemplate template) throws IOException,
            InterruptedException, AmazonClientException {
        logInfo(computer, listener, "bootstrap()");
        RemoteSshConnection bootstrapConn = null;
        try {
            int tries = bootstrapAuthTries;
            boolean isAuthenticated = false;
            logInfo(computer, listener, "Getting keypair...");
            KeyPair key = computer.getCloud().getKeyPair();
            logInfo(computer, listener,
                    String.format("Using private key %s (SHA-1 fingerprint %s)", key.getKeyName(), key.getKeyFingerprint()));
            while (tries-- > 0) {
                logInfo(computer, listener, "Authenticating as " + computer.getRemoteAdmin());
                try {
                    bootstrapConn = connectToSsh(computer, listener, template,computer.getRemoteAdmin(), computer.getNode().getAdminPassword().getPlainText());
                    isAuthenticated = true;
                } catch (RemoteSshConnection.AuthenticationException e) {
                    logWarning(computer, listener, "Authentication failed. Trying again...");
                    Thread.sleep(bootstrapAuthSleepMs);
                }
            }
            if (!isAuthenticated) {
                logWarning(computer, listener, "Authentication failed");
                return false;
            }
        } finally {
            if (bootstrapConn != null) {
                bootstrapConn.close();
            }
        }
        return true;
    }

    private RemoteSshConnection connectToSsh(EC2Computer computer, TaskListener listener, SlaveTemplate template, String username, String password) throws AmazonClientException,
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
                    logInfo(computer, listener, "empty instanceId for Spot Slave.");
                    throw new IOException("goto sleep");
                }

                if ("0.0.0.0".equals(host)) {
                    logWarning(computer, listener, "Invalid host 0.0.0.0, your host is most likely waiting for an ip address.");
                    throw new IOException("goto sleep");
                }

                int port = computer.getSshPort();
                Integer slaveConnectTimeout = Integer.getInteger("jenkins.ec2.slaveConnectTimeout", 10000);
                logInfo(computer, listener, "Connecting to " + host + " on port " + port + ", with timeout " + slaveConnectTimeout
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
                    logInfo(computer, listener, "Using HTTP Proxy Configuration");
                }
                RemoteSshConnection conn = RemoteSshConnection.getPasswordAuthenticatedClient(host,port,proxyData,new EC2WindowsSSHLauncher.ServerHostKeyVerifierImpl(computer,listener),slaveConnectTimeout,slaveConnectTimeout,username,password);
                logInfo(computer, listener, "Connected via SSH.");
                return conn; // successfully connected
            } catch (IOException e) {
                // keep retrying until SSH comes up
                logInfo(computer, listener, "Failed to connect via ssh: " + e.getMessage());

                // If the computer was set offline because it's not trusted, we avoid persisting in connecting to it.
                // The computer is offline for a long period
                if (computer.isOffline() && StringUtils.isNotBlank(computer.getOfflineCauseReason()) && computer.getOfflineCauseReason().equals(Messages.OfflineCause_SSHKeyCheckFailed())) {
                    throw new AmazonClientException("The connection couldn't be established and the computer is now offline", e);
                } else {
                    logInfo(computer, listener, "Waiting for SSH to come up. Sleeping 5.");
                    Thread.sleep(5000);
                }
            }
        }
    }


    private static String getEC2HostAddress (EC2Computer computer, SlaveTemplate template) throws
        InterruptedException {
            Instance instance = computer.updateInstanceDescription();
            ConnectionStrategy strategy = template.connectionStrategy;
            return EC2HostAddressProvider.unix(instance, strategy);
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
                return true;
                //SlaveTemplate template = computer.getSlaveTemplate();
                //return template != null && template.getHostKeyVerificationStrategy().getStrategy().verify(computer, new HostKey(serverHostKeyAlgorithm, serverHostKey), listener);
            }
        }



        @Override
        public Descriptor<ComputerLauncher> getDescriptor () {
            throw new UnsupportedOperationException();
        }

    }
