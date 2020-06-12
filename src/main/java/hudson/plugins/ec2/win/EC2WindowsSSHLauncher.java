package hudson.plugins.ec2.win;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.ec2.model.KeyPair;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.TaskListener;
import hudson.os.WindowsUtil;
import hudson.plugins.ec2.*;
import hudson.plugins.ec2.ssh.SshCredential;
import hudson.plugins.ec2.ssh.SshHelper;
import hudson.plugins.ec2.util.LogHelper;
import hudson.plugins.ec2.util.RemoteLongProcess;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Listener;
import hudson.slaves.ComputerLauncher;
import jenkins.model.Jenkins;

import java.io.EOFException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.concurrent.TimeUnit;

public class EC2WindowsSSHLauncher extends EC2ComputerLauncher {
    private static final String AGENT_JAR = "remoting.jar";

    final long sleepBetweenAttempts = TimeUnit.SECONDS.toMillis(10);
    private final static LogHelper logHelper = new LogHelper(EC2WindowsSSHLauncher.class.getName());

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
        WindowsData windowsData = (WindowsData) template.getAmiType();
        if (template == null) {
            throw new IOException("Could not find corresponding slave template for " + computer.getDisplayName());
        }
        final RemoteSshConnection conn;
        RemoteSshConnection cleanupConn = null;


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

                logHelper.logInfo(computer, listener, "Node still not ready. Current status: " + readinessNode.getEc2ReadinessStatus());
                Thread.sleep(readinessSleepMs);
            }

            if (!readinessNode.isReady()) {
                throw new AmazonClientException("Node still not ready, timed out after " + (readinessTries * readinessSleepMs / 1000) + "s with status " + readinessNode.getEc2ReadinessStatus());
            }
        }

        logHelper.logInfo(computer, listener, "Launching instance: " + node.getInstanceId());


        try {
            boolean isBootstrapped = SshHelper.bootstrap(computer, listener, template);
            if (isBootstrapped) {
                // connect fresh as ROOT
                logHelper.logInfo(computer, listener, "connect fresh");
                try {
                    cleanupConn = SshHelper.connectToSsh(computer, listener, template, new SshCredential(computer.getRemoteAdmin(), computer.getNode().getAdminPassword().getPlainText(),null));
                }
                catch (RemoteSshConnection.AuthenticationException e){
                    logHelper.logWarning(computer, listener, "Authentication failed");
                    return; // failed to connect
                }
                KeyPair key = computer.getCloud().getKeyPair();
            } else {
                logHelper.logWarning(computer, listener, "bootstrapresult failed");
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
                logHelper.logInfo(computer, listener, "Executing init script");
                conn.writeRemoteFile( tmpDir + ".jenkins-init", initScript.getBytes("UTF-8"));
                conn.executeProcess(tmpDir + "/init.bat", logger);

                logger.println("init script ran? successfully");
            }

            // Always copy so we get the most recent slave.jar
            logHelper.logInfo(computer, listener, "Copying remoting.jar to: " + tmpDir);
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


    private static int readinessSleepMs = 1000;
    private static int readinessTries = 120;







        /**
         * Our host key verifier just pick up the right strategy and call its verify method.
         */


        @Override
        public Descriptor<ComputerLauncher> getDescriptor () {
            throw new UnsupportedOperationException();
        }

    }
