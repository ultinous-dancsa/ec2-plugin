package hudson.plugins.ec2;

import com.trilead.ssh2.*;
import hudson.plugins.ec2.util.RemoteLongProcess;
import hudson.plugins.ec2.util.RemoteSshLongProcess;
import hudson.util.IOUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class RemoteSshConnection extends RemoteConnection {

    Connection connection = null;

    private RemoteSshConnection(String hostname, int port, ServerHostKeyVerifier verifier, int connectTimeout, int kexTimeout, HTTPProxyData proxyData) throws IOException {
        connection = new Connection(hostname, port);
        if(proxyData != null){
            connection.setProxyData(proxyData);
        }
        connection.connect(verifier,connectTimeout,kexTimeout);
    }

    public static RemoteSshConnection getPasswordAuthenticatedClient(String hostname, int port,  HTTPProxyData proxy, ServerHostKeyVerifier verifier,
                                                                     int connectTimeout, int kexTimeout, String username, String password) throws IOException, AuthenticationException {
        RemoteSshConnection conn = new RemoteSshConnection(hostname, port, verifier,connectTimeout,kexTimeout, proxy);
        if(! conn.connection.authenticateWithPassword(username,password)){
            throw new AuthenticationException();
        }
        return conn;
    }

    public static RemoteSshConnection getPubkeyAuthenticatedClient(String hostname, int port, HTTPProxyData proxy, ServerHostKeyVerifier verifier,
                                                                   int connectTimeout, int kexTimeout, String username, char[] pemPrivateKey) throws IOException, AuthenticationException {
        RemoteSshConnection conn = new RemoteSshConnection(hostname, port, verifier,connectTimeout,kexTimeout, proxy);
        if(!conn.connection.authenticateWithPublicKey(username,pemPrivateKey,"")){
            throw new AuthenticationException();
        }
        return conn;
    }


    @Override
    public void writeRemoteFile(String dest, String content) throws IOException {
        writeRemoteFile(dest,content.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void writeRemoteFile(String dest, byte[] content) throws IOException {
        File file = new File(dest);
        String path = (file.getParent() == null)?"":file.getParent();

        SCPClient scp = connection.createSCPClient();
        scp.put(content, file.getName(), path, "0700");

    }

    @Override
    public void writeRemoteFile(String dest, InputStream content) throws IOException {
        throw new UnsupportedOperationException(); //no trilead stream upload, only download in the lib
    }

    @Override
    public int executeProcess(String cmd) throws IOException {
        return executeProcess(cmd,null);
    }

    @Override
    public int executeProcess(String cmd, OutputStream output) throws IOException {
        Session sess = connection.openSession();
        sess.requestDumbPTY();
        sess.execCommand(cmd);
        if( output != null){
            IOUtils.copy(sess.getStdout(),output);
        }
        for (int i = 0; i < 10; i++) {
            Integer r = sess.getExitStatus();
            if (r != null)
                return r;
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {

            }
        }
        return -1;
    }

    @Override
    public RemoteLongProcess runProcess(String cmd) throws IOException {
        Session sess = connection.openSession();
        sess.execCommand(cmd);
        return new RemoteSshLongProcess(sess);
    }

    @Override
    public void close() {
        connection.close();
    }


    public static class AuthenticationException extends Exception{}


}
