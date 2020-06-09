package hudson.plugins.ec2;

import hudson.plugins.ec2.util.RemoteLongProcess;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class RemoteSshConnection extends RemoteConnection {
    @Override
    public void writeRemoteFile(String dest, String content) throws IOException {

    }

    @Override
    public void writeRemoteFile(String dest, InputStream content) throws IOException {

    }

    @Override
    public int executeProcess(String cmd) throws IOException {
        return 0;
    }

    @Override
    public int executeProcess(String cmd, OutputStream output) throws IOException {
        return 0;
    }

    @Override
    public RemoteLongProcess runProcess(String cmd) {
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public boolean exists(String path) throws IOException {
        return false;
    }
}
