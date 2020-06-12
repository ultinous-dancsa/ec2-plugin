/*
 * The MIT License
 *
 * Copyright (c) 2004-, Kohsuke Kawaguchi, Sun Microsystems, Inc., and a number of other of contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.plugins.ec2.ssh;

import hudson.FilePath;
import hudson.Util;
import hudson.ProxyConfiguration;
import hudson.model.Descriptor;
import hudson.model.TaskListener;
import hudson.plugins.ec2.*;
import hudson.plugins.ec2.ssh.verifiers.CheckNewHardStrategy;
import hudson.plugins.ec2.ssh.verifiers.HostKey;
import hudson.plugins.ec2.ssh.verifiers.Messages;
import hudson.plugins.ec2.util.RemoteLongProcess;
import hudson.plugins.ec2.util.RemoteSshLongProcess;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Listener;
import hudson.slaves.CommandLauncher;
import hudson.slaves.ComputerLauncher;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.model.Jenkins;

import org.apache.commons.io.IOUtils;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.KeyPair;
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.HTTPProxyData;
import com.trilead.ssh2.SCPClient;
import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.Session;
import org.apache.commons.lang.StringUtils;

/**
 * {@link ComputerLauncher} that connects to a Unix slave on EC2 by using SSH.
 *
 * @author Kohsuke Kawaguchi
 */
public class EC2UnixLauncher extends EC2ComputerLauncher {

    private static final Logger LOGGER = Logger.getLogger(EC2UnixLauncher.class.getName());

    private static final String BOOTSTRAP_AUTH_SLEEP_MS = "jenkins.ec2.bootstrapAuthSleepMs";
    private static final String BOOTSTRAP_AUTH_TRIES= "jenkins.ec2.bootstrapAuthTries";
    private static final String READINESS_SLEEP_MS = "jenkins.ec2.readinessSleepMs";
    private static final String READINESS_TRIES= "jenkins.ec2.readinessTries";

    private static int bootstrapAuthSleepMs = 30000;
    private static int bootstrapAuthTries = 30;

    private static int readinessSleepMs = 1000;
    private static int readinessTries = 120;

    static  {
        String prop = System.getProperty(BOOTSTRAP_AUTH_SLEEP_MS);
        if (prop != null)
            bootstrapAuthSleepMs = Integer.parseInt(prop);
        prop = System.getProperty(BOOTSTRAP_AUTH_TRIES);
        if (prop != null)
            bootstrapAuthTries = Integer.parseInt(prop);
        prop = System.getProperty(READINESS_TRIES);
        if (prop != null)
            readinessTries = Integer.parseInt(prop);
        prop = System.getProperty(READINESS_SLEEP_MS);
        if (prop != null)
            readinessSleepMs = Integer.parseInt(prop);
    }

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

    protected String buildUpCommand(EC2Computer computer, String command) {
        String remoteAdmin = computer.getRemoteAdmin();
        if (remoteAdmin != null && !remoteAdmin.equals("root")) {
            command = computer.getRootCommandPrefix() + " " + command;
        }
        return command;
    }

    @Override
    protected void launchScript(EC2Computer computer, TaskListener listener) throws IOException,
            AmazonClientException, InterruptedException {
        final RemoteSshConnection conn;
        RemoteSshConnection cleanupConn = null; // java's code path analysis for final
                                       // doesn't work that well.
        boolean successful = false;
        PrintStream logger = listener.getLogger();
        EC2AbstractSlave node = computer.getNode();
        SlaveTemplate template = computer.getSlaveTemplate();

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
            boolean isBootstrapped = SshHelper.bootstrap(computer, listener, template);
            if (isBootstrapped) {
                // connect fresh as ROOT
                logInfo(computer, listener, "connect fresh as root");
                KeyPair key = computer.getCloud().getKeyPair();
                try {
                    cleanupConn = SshHelper.connectToSsh(computer, listener, template, new SshCredential(computer.getRemoteAdmin(), null, key.getKeyMaterial().toCharArray()));
                } catch (RemoteSshConnection.AuthenticationException e) {
                    logWarning(computer, listener, "Authentication failed");
                    return; // failed to connect as root.

                }
            } else {
                logWarning(computer, listener, "bootstrapresult failed");
                return; // bootstrap closed for us.
            }
            conn = cleanupConn;

            String initScript = node.initScript;
            String tmpDir = (Util.fixEmptyAndTrim(node.tmpDir) != null ? node.tmpDir : "/tmp");

            logInfo(computer, listener, "Creating tmp directory (" + tmpDir + ") if it does not exist");
            conn.executeProcess("mkdir -p "+ tmpDir, logger);

            if (initScript != null && initScript.trim().length() > 0
                    && conn.executeProcess("test -e ~/.hudson-run-init", logger) != 0) {
                logInfo(computer, listener, "Executing init script");
                conn.writeRemoteFile(tmpDir+"init.sh", initScript);
                conn.executeProcess(buildUpCommand(computer, tmpDir + "/init.sh"));


                int exitStatus = conn.executeProcess(buildUpCommand(computer, tmpDir + "/init.sh"), logger);
                if (exitStatus != 0) {
                    logWarning(computer, listener, "init script failed: exit code=" + exitStatus);
                    return;
                }
                logInfo(computer, listener, "Creating ~/.hudson-run-init");

                exitStatus = conn.executeProcess(buildUpCommand(computer, "touch ~/.hudson-run-init"));
                if (exitStatus != 0) {
                    logWarning(computer, listener, "init script failed: exit code=" + exitStatus);
                    return;
                }

            }

            // TODO: parse the version number. maven-enforcer-plugin might help
            executeRemote(computer, conn, "java -fullversion", "sudo yum install -y java-1.8.0-openjdk.x86_64", logger, listener);
            executeRemote(computer, conn, "which scp", "sudo yum install -y openssh-clients", logger, listener);

            // Always copy so we get the most recent slave.jar
            logInfo(computer, listener, "Copying remoting.jar to: " + tmpDir);
            conn.writeRemoteFile(tmpDir+"remoting.jar", Jenkins.get().getJnlpJars("remoting.jar").readFully());

            final String jvmopts = node.jvmopts;
            final String prefix = computer.getSlaveCommandPrefix();
            final String suffix = computer.getSlaveCommandSuffix();
            final String remoteFS = node.getRemoteFS();
            final String workDir = Util.fixEmptyAndTrim(remoteFS) != null ? remoteFS : tmpDir;
            String launchString = prefix + " java " + (jvmopts != null ? jvmopts : "") + " -jar " + tmpDir + "/remoting.jar -workDir " + workDir + suffix;
           // launchString = launchString.trim();

            SlaveTemplate slaveTemplate = computer.getSlaveTemplate();

            if (slaveTemplate != null && slaveTemplate.isConnectBySSHProcess()) {
                File identityKeyFile = createIdentityKeyFile(computer);

                try {
                    // Obviously the master must have an installed ssh client.
                    // Depending on the strategy selected on the UI, we set the StrictHostKeyChecking flag
                    String sshClientLaunchString = String.format("ssh -o StrictHostKeyChecking=%s -i %s %s@%s -p %d %s", slaveTemplate.getHostKeyVerificationStrategy().getSshCommandEquivalentFlag(), identityKeyFile.getAbsolutePath(), node.remoteAdmin, SshHelper.getEC2HostAddress(computer, template), node.getSshPort(), launchString);

                    logInfo(computer, listener, "Launching remoting agent (via SSH client process): " + sshClientLaunchString);
                    CommandLauncher commandLauncher = new CommandLauncher(sshClientLaunchString, null);
                    commandLauncher.launch(computer, listener);
                } finally {
                    if(!identityKeyFile.delete()) {
                        LOGGER.log(Level.WARNING, "Failed to delete identity key file");
                    }
                }
            } else {
                logInfo(computer, listener, "Launching remoting agent (via Trilead SSH2 Connection): " + launchString);
                RemoteLongProcess process = conn.runProcess(launchString);
                computer.setChannel(process.getStdout(), process.getStdin(), logger, new Listener() {
                    @Override
                    public void onClosed(Channel channel, IOException cause) {
                        process.destroy();
                        conn.close();
                    }
                });
            }

            successful = true;
        } finally {
            if (cleanupConn != null && !successful)
                cleanupConn.close();
        }
    }

    private boolean executeRemote(EC2Computer computer, RemoteConnection conn, String checkCommand,  String command, PrintStream logger, TaskListener listener)
            throws IOException, InterruptedException {
        logInfo(computer, listener,"Verifying: " + checkCommand);
        if (conn.executeProcess(checkCommand, logger) != 0) {
            logInfo(computer, listener, "Installing: " + command);
            if (conn.executeProcess(command, logger) != 0) {
                logWarning(computer, listener, "Failed to install: " + command);
                return false;
            }
        }
        return true;
    }

    private File createIdentityKeyFile(EC2Computer computer) throws IOException {
        String privateKey = computer.getCloud().getPrivateKey().getPrivateKey();
        File tempFile = File.createTempFile("ec2_", ".pem");

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(tempFile);
            OutputStreamWriter writer = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8);
            try {
                writer.write(privateKey);
                writer.flush();
            } finally {
                writer.close();
                fileOutputStream.close();
            }
            FilePath filePath = new FilePath(tempFile);
            filePath.chmod(0400); // octal file mask - readonly by owner
            return tempFile;
        } catch (Exception e) {
            if (!tempFile.delete()) {
                LOGGER.log(Level.WARNING, "Failed to delete identity key file");
            }
            throw new IOException("Error creating temporary identity key file for connecting to EC2 agent.", e);
        }
    }





    



    @Override
    public Descriptor<ComputerLauncher> getDescriptor() {
        throw new UnsupportedOperationException();
    }
}
