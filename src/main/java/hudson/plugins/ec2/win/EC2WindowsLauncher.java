package hudson.plugins.ec2.win;

import com.amazonaws.services.ec2.model.KeyPair;
import hudson.model.Descriptor;
import hudson.model.TaskListener;
import hudson.plugins.ec2.*;
import hudson.plugins.ec2.ssh.SshCredential;
import hudson.plugins.ec2.ssh.SshHelper;
import hudson.plugins.ec2.util.LogHelper;
import hudson.plugins.ec2.util.RemoteLongProcess;
import hudson.plugins.ec2.win.winrm.WindowsProcess;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Listener;
import hudson.slaves.ComputerLauncher;
import hudson.Util;
import hudson.os.WindowsUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import hudson.slaves.OfflineCause;
import javax.annotation.Nonnull;

import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.GetPasswordDataRequest;
import com.amazonaws.services.ec2.model.GetPasswordDataResult;

import javax.net.ssl.SSLException;

public class EC2WindowsLauncher extends EC2ComputerLauncher {
    private static final String AGENT_JAR = "remoting.jar";
    RemoteConnection  remoteConnection;
    private static final LogHelper logHelper = new LogHelper(EC2WindowsLauncher.class.getName());
    private static final int readinessSleepMs = 1000;
    private static final int readinessTries = 120;
    final long sleepBetweenAttempts = TimeUnit.SECONDS.toMillis(10);

    @Override
    protected void launchScript(EC2Computer computer, TaskListener listener) throws IOException,
            AmazonClientException, InterruptedException {
        final PrintStream logger = listener.getLogger();
        EC2AbstractSlave node = computer.getNode();
        if (node == null) {
            logger.println("Unable to fetch node information");
            return;
        }
        final SlaveTemplate template = computer.getSlaveTemplate();
        if (template == null) {
            throw new IOException("Could not find corresponding slave template for " + computer.getDisplayName());
        }

        if (node == null) {
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

                logHelper.logInfo(computer, listener, "Node still not ready. Current status: " + readinessNode.getEc2ReadinessStatus());
                Thread.sleep(readinessSleepMs);
            }

            if (!readinessNode.isReady()) {
                throw new AmazonClientException("Node still not ready, timed out after " + (readinessTries * readinessSleepMs / 1000) + "s with status " + readinessNode.getEc2ReadinessStatus());
            }
        }
        logHelper.logInfo(computer, listener, "Launching instance: " + node.getInstanceId());




        WindowsData windowsData = (WindowsData) template.getAmiType();
        if (windowsData.getConnectWindowsBySSH()) {
            RemoteSshConnection cleanupConn = null;

            try {
                boolean isBootstrapped = SshHelper.bootstrap(computer, listener, template);
                if (isBootstrapped) {
                    // connect fresh as ROOT
                    logHelper.logInfo(computer, listener, "connect fresh");
                    try {
                        cleanupConn = SshHelper.connectToSsh(computer, listener, template, new SshCredential(computer.getRemoteAdmin(), computer.getNode().getAdminPassword().getPlainText(), null));
                    } catch (RemoteSshConnection.AuthenticationException e) {
                        logHelper.logWarning(computer, listener, "Authentication failed");
                        return; // failed to connect
                    }
                    KeyPair key = computer.getCloud().getKeyPair();
                } else {
                    logHelper.logWarning(computer, listener, "bootstrapresult failed");
                    return; // bootstrap closed for us.
                }
                remoteConnection = cleanupConn;

            }catch (EOFException eof) {
                // When we launch java with connection.execute(launchString... it keeps running, but if java is not installed
                //the computer.setChannel fails with EOFException because the stream is already closed. It fails on
                // setChannel - build - negotiate - is.read() == -1. Let's print a clear message to help diagnose the problem
                // In other case you see a EOFException which gives you few clues about the problem.
                logger.println("The stream with the java process on the instance was closed. Maybe java is not installed there.");
                eof.printStackTrace(logger);
                throw eof;
            } catch (Throwable ioe) {
                logger.println("Ouch:");
                ioe.printStackTrace(logger);
                throw ioe;
            }
        }else{
            remoteConnection = connectToWinRM(computer, node, template, logger);
        }


        
        try {
            String initScript = node.initScript;
            String tmpDir = (node.tmpDir != null && !node.tmpDir.equals("") ? WindowsUtil.quoteArgument(Util.ensureEndsWith(node.tmpDir,"\\"))
                    : "C:\\Windows\\Temp\\");
            //FIXME: SSH works with unix style paths
            if(windowsData.getConnectWindowsBySSH()){
                tmpDir = "C:/tmp/";
            }


            setupLaunch(logger,tmpDir,initScript);
            logger.println("remoting.jar sent remotely. Bootstrapping it");

            final String jvmopts = node.jvmopts;
            final String remoteFS = WindowsUtil.quoteArgument(node.getRemoteFS());
            final String workDir = Util.fixEmptyAndTrim(remoteFS) != null ? remoteFS : tmpDir;
            final String launchString = "java " + (jvmopts != null ? jvmopts : "") + " -jar " + tmpDir + AGENT_JAR + " -workDir " + workDir;
            logger.println("Launching:" + launchString);

            final RemoteLongProcess process = remoteConnection.runProcess(launchString);
            computer.setChannel(process.getStdout(), process.getStdin(), logger, new Listener() {
                @Override
                public void onClosed(Channel channel, IOException cause) {
                    process.destroy();
                    remoteConnection.close();
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
        }
    }



    private void setupLaunch(PrintStream logger, String tmpDir, String initScript) throws IOException, RemoteConnection.CommandException {
        logger.println("Checking if tmp directory exists");
        //if(!remoteFileExists(tmpDir)){
            logger.println("Creating tmp directory");
            remoteCreateDir(tmpDir,logger);
        //}

        if (initScript != null && initScript.trim().length() > 0 && !remoteFileExists(tmpDir + ".jenkins-init")) {
            logger.println("Executing init script");
            remoteConnection.writeRemoteFile(tmpDir + "init.bat", initScript);

            int exitCode = remoteConnection.executeProcess("cmd /c " + tmpDir + "init.bat", logger);

            if (exitCode != 0) {
                logger.println("init script failed: exit code=" + exitCode);
                throw new RemoteConnection.CommandException("init script failed: exit code=" + exitCode);
            }

            remoteConnection.writeRemoteFile(tmpDir + ".jenkins-init","init ran");
            logger.println("init script ran successfully");
        }
        remoteConnection.writeRemoteFile(tmpDir + AGENT_JAR, Jenkins.get().getJnlpJars(AGENT_JAR).readFully());
    }

    private boolean remoteFileExists(String path) throws IOException {
        if(remoteConnection instanceof RemoteWinRmConnection){
            return ((RemoteWinRmConnection)remoteConnection).exists(path);
        }else if (remoteConnection instanceof RemoteSshConnection){
            return ( 0 == remoteConnection.executeProcess("if((Test-Path \""+path+"\") -eq $True){exit 0}else{exit 1}"))?true:false;
        }else{
            throw new AssertionError();
        }
    }

    private void remoteCreateDir(String path, PrintStream logger) throws RemoteConnection.CommandException, IOException {
        if(remoteConnection instanceof RemoteWinRmConnection){
            if(0 != remoteConnection.executeProcess("if not exist " + path + " mkdir " + path)){
                throw new RemoteConnection.CommandException("Failed to create directory");
            }
        }else if (remoteConnection instanceof RemoteSshConnection){
            if(0 != remoteConnection.executeProcess("New-Item -ItemType Directory -Force -Path "+ path, logger)){
                throw new RemoteConnection.CommandException("Failed to create directory");
            }
        }else{
            throw new AssertionError();
        }

    }

    @Nonnull
    private RemoteConnection connectToWinRM(EC2Computer computer, EC2AbstractSlave node, SlaveTemplate template, PrintStream logger) throws AmazonClientException,
            InterruptedException {
        final long minTimeout = 3000;
        long timeout = node.getLaunchTimeoutInMillis(); // timeout is less than 0 when jenkins is booting up.
        if (timeout < minTimeout) {
            timeout = minTimeout;
        }
        final long startTime = System.currentTimeMillis();

        logger.println(node.getDisplayName() + " booted at " + node.getCreatedTime());
        boolean alreadyBooted = (startTime - node.getCreatedTime()) > TimeUnit.MINUTES.toMillis(3);
        RemoteWinRmConnection connection = null;
        while (true) {
            boolean allowSelfSignedCertificate = node.isAllowSelfSignedCertificate();

            try {
                long waitTime = System.currentTimeMillis() - startTime;
                if (waitTime > timeout) {
                    throw new AmazonClientException("Timed out after " + (waitTime / 1000)
                            + " seconds of waiting for winrm to be connected");
                }

                if (connection == null) {
                    Instance instance = computer.updateInstanceDescription();
                    String host = EC2HostAddressProvider.windows(instance, template.connectionStrategy);

                    // Check when host is null or we will keep trying and receiving a hostname cannot be null forever.
                    if (host == null || "0.0.0.0".equals(host)) {
                        logger.println("Invalid host (null or 0.0.0.0). Your host is most likely waiting for an IP address.");
                        throw new IOException("goto sleep");
                    }

                    if (!node.isSpecifyPassword()) {
                        GetPasswordDataResult result;
                        try {
                            result = node.getCloud().connect().getPasswordData(new GetPasswordDataRequest(instance.getInstanceId()));
                        } catch (Exception e) {
                            logger.println("Unexpected Exception: " + e.toString());
                            Thread.sleep(sleepBetweenAttempts);
                            continue;
                        }
                        String passwordData = result.getPasswordData();
                        if (passwordData == null || passwordData.isEmpty()) {
                            logger.println("Waiting for password to be available. Sleeping 10s.");
                            Thread.sleep(sleepBetweenAttempts);
                            continue;
                        }
                        String password = node.getCloud().getPrivateKey().decryptWindowsPassword(passwordData);
                        if (!node.getRemoteAdmin().equals("Administrator")) {
                            logger.println("WARNING: For password retrieval remote admin must be Administrator, ignoring user provided value");
                        }
                        logger.println("Connecting to " + "(" + host + ") with WinRM as Administrator");
                        connection = new RemoteWinRmConnection(host, "Administrator", password, allowSelfSignedCertificate, node.isUseHTTPS());
                    } else { //password Specified
                        logger.println("Connecting to " + "(" + host + ") with WinRM as " + node.getRemoteAdmin());
                        connection = new RemoteWinRmConnection(host, node.getRemoteAdmin(), node.getAdminPassword().getPlainText(), allowSelfSignedCertificate,node.isUseHTTPS());
                    }
                }

                if (!connection.pingFailingIfSSHHandShakeError()) {
                    logger.println("Waiting for WinRM to come up. Sleeping 10s.");
                    Thread.sleep(sleepBetweenAttempts);
                    continue;
                }

                if (!alreadyBooted || node.stopOnTerminate) {
                    logger.println("WinRM service responded. Waiting for WinRM service to stabilize on "
                            + node.getDisplayName());
                    Thread.sleep(node.getBootDelay());
                    alreadyBooted = true;
                    logger.println("WinRM should now be ok on " + node.getDisplayName());
                    if (!connection.pingFailingIfSSHHandShakeError()) {
                        logger.println("WinRM not yet up. Sleeping 10s.");
                        Thread.sleep(sleepBetweenAttempts);
                        continue;
                    }
                }

                logger.println("Connected with WinRM.");
                return connection; // successfully connected
            } catch (IOException e) {
                if (e instanceof SSLException) {
                    // To avoid reconnecting continuously
                    computer.setTemporarilyOffline(true, OfflineCause.create(Messages._OfflineCause_SSLException()));
                    // avoid waiting and trying again, this connection needs human intervention to change the certificate
                    throw new AmazonClientException("The SSL connection failed while negotiating SSL", e);
                }
                logger.println("Waiting for WinRM to come up. Sleeping 10s.");
                Thread.sleep(sleepBetweenAttempts);
            }
        }
    }

    @Override
    public Descriptor<ComputerLauncher> getDescriptor() {
        throw new UnsupportedOperationException();
    }
}
