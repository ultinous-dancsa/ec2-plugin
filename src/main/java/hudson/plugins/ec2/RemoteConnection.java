package hudson.plugins.ec2;

import hudson.plugins.ec2.util.RemoteLongProcess;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class RemoteConnection {

    abstract public void writeRemoteFile(String dest, String content) throws IOException;
    abstract public void writeRemoteFile(String dest, byte[] content) throws IOException;

    abstract public void writeRemoteFile(String dest, InputStream content) throws  IOException;
    abstract public int executeProcess(String cmd) throws IOException;
    abstract public int executeProcess(String cmd, OutputStream output) throws IOException;
    abstract public RemoteLongProcess runProcess(String cmd) throws IOException;
    abstract public void close();

    public abstract boolean exists(String path) throws IOException;

    public static class Iotpuple{
        public OutputStream stdin;
        public InputStream stdout;

        public Iotpuple(OutputStream stdin, InputStream stdout) {
            this.stdin = stdin;
            this.stdout = stdout;
        }
    }


}
