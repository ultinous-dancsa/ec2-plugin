package hudson.plugins.ec2;

import hudson.plugins.ec2.util.RemoteLongProcess;
import hudson.plugins.ec2.util.RemoteWinLongProcess;
import hudson.plugins.ec2.win.WinConnection;
import hudson.plugins.ec2.win.winrm.WindowsProcess;
import hudson.util.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class RemoteWinRmConnection extends RemoteConnection {
    WinConnection connection = null;

    public RemoteWinRmConnection(String host, String username, String password, boolean allowSelfSignedCertificate, boolean https) {
        connection = new WinConnection(host,username,password,allowSelfSignedCertificate);
        if(https){
            connection.setUseHTTPS(true);
        }

    }

    @Override
    public void writeRemoteFile(String dest, String content) throws IOException {
        this.writeRemoteFile(dest,new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public void writeRemoteFile(String dest, byte[] content) throws IOException {
        this.writeRemoteFile(dest,new ByteArrayInputStream(content));

    }


    @Override
    public void writeRemoteFile(String dest, InputStream content) throws IOException {
        OutputStream out = connection.putFile(dest);
        IOUtils.copy(content,out);
        out.close();
    }

    @Override
    public int executeProcess(String cmd) throws IOException {
        return this.executeProcess(cmd,null);
    }

    @Override
    public int executeProcess(String cmd, OutputStream output) throws IOException {
        WindowsProcess process = connection.execute(cmd);
        if( output != null){
            IOUtils.copy(process.getStdout(),output);
        }
        return process.waitFor();
    }

    @Override
    public RemoteLongProcess runProcess(String cmd) {
        WindowsProcess process = connection.execute(cmd);
        return new RemoteWinLongProcess(process);
    }

    public boolean pingFailingIfSSHHandShakeError() throws IOException {
        return connection.pingFailingIfSSHHandShakeError();
    }

    public boolean exists(String path) throws IOException {
        return connection.exists(path);
    }

        @Override
    public void close() {
        connection.close();
    }


}